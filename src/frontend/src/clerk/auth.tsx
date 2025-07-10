import { lazy, ReactNode, useContext, useEffect, useRef } from "react";
import { AuthContext } from "@/contexts/authContext";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import { useLogout as useLogoutMutation } from "@/controllers/API/queries/auth";
import useAuthStore from "@/stores/authStore";
import { ClerkProvider, useAuth, useClerk, useUser } from "@clerk/clerk-react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

// Clerk constants
export const IS_CLERK_AUTH =
  String(import.meta.env.VITE_CLERK_AUTH_ENABLED).toLowerCase() === "true";
console.log("IS_CLERK_AUTH:", IS_CLERK_AUTH);

console.log(useAuthStore.getState().isAuthenticated, "useAuthStore.isAuthenticated");
export const CLERK_PUBLISHABLE_KEY = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY || "";
export const CLERK_DUMMY_PASSWORD = "clerk_dummy_password";

// Backend synchronization helpers
export async function ensureLangflowUser(token: string, username: string): Promise<boolean> {
  console.log("[ensureLangflowUser] START");

  try {
    const whoAmIRes = await api.get(`${getURL("USERS")}/whoami`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    console.log(`[ensureLangflowUser] user exists: ${username}`);
    return false;
  } catch (err: any) {
    console.log("[ensureLangflowUser] inside catch block");

    const status = err?.response?.status;
    console.warn(`[ensureLangflowUser] whoami failed (${status})`);

    if (status === 401) {
      console.log("[ensureLangflowUser] trying to create user...");
      const createRes = await api.post(
        `${getURL("USERS")}/`,
        { username, password: CLERK_DUMMY_PASSWORD },
        { headers: { Authorization: `Bearer ${token}` } },
      );
      console.log(`[ensureLangflowUser] created user: ${createRes.status}`);
      return true;
    }

    throw err;
  }
}

export async function backendLogin(username: string) {
  const res = await api.post(
    `${getURL("LOGIN")}`,
    new URLSearchParams({
      username,
      password: CLERK_DUMMY_PASSWORD,
    }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    },
  );
  return res.data;
}

// Component that syncs Clerk session with backend
// auth.tsx
export function ClerkAuthAdapter() {
  const { getToken, isSignedIn, sessionId } = useAuth();
  const { user } = useUser();
  const { login } = useContext(AuthContext);
  const { mutateAsync: logout } = useLogout();
  const prevSession = useRef<string | null>(null);

  useEffect(() => {
      // only run when we go from "no session" → "new session"
    async function syncToken() {
      if (isSignedIn) {
        if (sessionId === prevSession.current) {
          return;
        }

        prevSession.current = sessionId;
        console.log("[ClerkAuthAdapter] new Clerk session, syncing…");
        const token = await getToken();
        if (token) {
          const username =
            user?.username ||
            user?.primaryEmailAddress?.emailAddress ||
            user?.id ||
            "clerk_user";
          try {
            const justCreated = await ensureLangflowUser(token, username);
            console.log("[ClerkAuthAdapter] justCreated:", justCreated, "for user:", username);
            if (justCreated) {
              console.log("[ClerkAuthAdapter] user created → signing out");
              await logout();
              window.location.replace("/login");
              return;
            }

            try {
              const { refresh_token } = await backendLogin(username);
              login(token, "login", refresh_token);
              window.location.replace("/");
              console.log("[ClerkAuthAdapter] backend login successful");
            } catch (loginErr) {
              console.error("[ClerkAuthAdapter] backend login failed", loginErr);
            }
          } catch {
            // ignore errors and continue login
          }
        }
    }
    }
    syncToken();
  }, [isSignedIn, sessionId, getToken, user, login, logout]);

  return null;
}

// Provider that wraps the app with Clerk when enabled
export function ClerkAuthProvider({ children }: { children: ReactNode }) {
  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
      <ClerkAuthAdapter />
      {children}
    </ClerkProvider>
  );
}

// Logout hook that also signs out from Clerk
export function useLogout(options?: Parameters<typeof useLogoutMutation>[0]) {
  const { mutate, mutateAsync, ...rest } = useLogoutMutation(options);
  const { signOut } = IS_CLERK_AUTH ? useClerk() : { signOut: async () => {} };

  const clerkSignOut = async () => {
    if (IS_CLERK_AUTH) {
      try {
        await signOut();
      } catch (err) {
        console.error("Clerk signOut failed:", err);
      }
    }
  };

  const wrappedMutate: typeof mutate = (...args) => {
    clerkSignOut().finally(() => mutate(...args));
  };

  const wrappedMutateAsync: typeof mutateAsync = async (...args) => {
    await clerkSignOut();
    return mutateAsync(...args);
  };

  return { mutate: wrappedMutate, mutateAsync: wrappedMutateAsync, clerkSignOut, ...rest };
}

const LazyApp = lazy(() => import("../customization/custom-App"));

// App wrapper that conditionally enables Clerk
const queryClient = new QueryClient();

export function AppWithProvider() {
  return (
    <QueryClientProvider client={queryClient}>
      {IS_CLERK_AUTH ? (
        <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
          <ClerkAuthAdapter />
          <LazyApp />
        </ClerkProvider>
      ) : (
        <LazyApp />
      )}
    </QueryClientProvider>
  );
} 

// Mock mutation used when Clerk auth is enabled
export const mockClerkMutation = {
  mutate: () => {},
  mutateAsync: async () => undefined,
  isError: false,
  isIdle: true,
  isPending: false,
  isSuccess: true,
  reset: () => {},
  status: "success",
  variables: undefined,
  data: undefined,
  error: null,
} as any;

export default AppWithProvider;
