import { lazy, ReactNode, useContext, useEffect, useRef } from "react";
import { AuthContext } from "@/contexts/authContext";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import { useLogout as useLogoutMutation } from "@/controllers/API/queries/auth";
import useAuthStore from "@/stores/authStore";
import { ClerkProvider, useAuth, useClerk, useUser } from "@clerk/clerk-react";
import { Users } from "@/types/api";
import { IS_CLERK_AUTH, CLERK_PUBLISHABLE_KEY, CLERK_DUMMY_PASSWORD } from "./constants";
import { LANGFLOW_ACCESS_TOKEN } from "@/constants/constants";
import { Cookies } from "react-cookie";
console.log("IS_CLERK_AUTH:", IS_CLERK_AUTH);
console.log(useAuthStore.getState().isAuthenticated, "useAuthStore.isAuthenticated");

// Backend synchronization helpers
export async function ensureLangflowUser(token: string, username: string): Promise<{
  justCreated: boolean;
  user: Users | null;
}> {
  console.log("[ensureLangflowUser] START");

  try {
    const whoAmIRes = await api.get<Users>(`${getURL("USERS")}/whoami`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const user = whoAmIRes.data;
    // useAuthStore.getState().setUserData(user);
    console.log(`[ensureLangflowUser] user exists: ${username}`);
    return { justCreated: false, user };
  } catch (err: any) {
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
      return { justCreated: true, user: null };
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
export function ClerkAuthAdapter() {
  const { getToken, isSignedIn, sessionId } = useAuth();
  const { user } = useUser();
  const { login } = useContext(AuthContext);
  const { mutateAsync: logout } = useLogout();
  const prevSession = useRef<string | null>(null);
  const justLoggedIn = useRef(false);
  console.log('[ClerkAuthAdapter] login function:', login);
  const cookie = new Cookies();

  useEffect(() => {
    const syncToken = async () => {
      if (!isSignedIn || sessionId === prevSession.current) return;

      prevSession.current = sessionId;
      console.log("[ClerkAuthAdapter] New Clerk session detected");

      const token = await getToken();
      if (!token) {
        console.warn("[ClerkAuthAdapter] No Clerk token available");
        return;
      }
      const current = cookie.get(LANGFLOW_ACCESS_TOKEN);
      if (token === current) {
        return;
      }else{
        console.log("[ClerkAuthAdapter] Clerk token changed, syncing...");
        cookie.set(LANGFLOW_ACCESS_TOKEN, token, { path: "/" });
        useAuthStore.getState().setAccessToken?.(token); // if you have this
      }
      const username =
        user?.username ||
        user?.primaryEmailAddress?.emailAddress ||
        user?.id ||
        "clerk_user";

      try {
        const { justCreated, user } = await ensureLangflowUser(token, username);

        if (justCreated=== true && !user) {
          console.warn("[ClerkAuthAdapter] User created → Signing out to restart session");
          await logout();
          window.location.replace("/login");
          return;
        }

        const { refresh_token } = await backendLogin(username);
        console.log("[ClerkAuthAdapter] Backend login successful");
        console.log('[ClerkAuthAdapter] About to call login:', login);
        login(token, "login", refresh_token);
        justLoggedIn.current = true;
        console.log("[ClerkAuthAdapter] login complete");
      } catch (err) {
        if (!justLoggedIn.current) {
          console.error("[ClerkAuthAdapter] syncToken error:", err);
          await logout();
        } else {
          console.warn("[ClerkAuthAdapter] Skipping logout due to recent login");
        }
      }
    };

    syncToken();
  }, [isSignedIn, sessionId, getToken, user, login, logout]);

  return null;
}

// Provider that wraps the app with Clerk when enabled
export function ClerkAuthProvider({ children }: { children: ReactNode }) {
  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
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

// App wrapper that conditionally enables Clerk
const LazyApp = lazy(() => import("../customization/custom-App"));

export function AppWithProvider() {
  return IS_CLERK_AUTH ? (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
      <LazyApp />
    </ClerkProvider>
  ) : (
      <LazyApp />
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
