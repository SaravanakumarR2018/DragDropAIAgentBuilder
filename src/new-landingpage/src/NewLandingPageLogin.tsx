import {
  OrganizationList,
  SignIn,
  SignedIn,
  SignedOut,
  useAuth,
  useClerk,
  useOrganization,
  useUser,
} from "@clerk/clerk-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useCookies } from "react-cookie";
import { create } from "zustand";

const CLERK_DUMMY_PASSWORD = "clerk_dummy_password";
const LANGFLOW_ACCESS_TOKEN = "access_token_lf";
const LANGFLOW_REFRESH_TOKEN = "refresh_token_lf";
const LANGFLOW_AUTO_LOGIN_OPTION = "auto_login_lf";
const API_BASE = (import.meta.env.VITE_LANGFLOW_API_BASE ?? "/api/v1/").replace(/\/?$/, "/");

class HttpError extends Error {
  status: number;
  data: Record<string, any> | null;

  constructor(status: number, message: string, data: Record<string, any> | null) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

function apiUrl(path: string) {
  return `${API_BASE}${path.replace(/^\/+/, "")}`;
}

type AuthState = {
  isAuthenticated: boolean;
  accessToken: string | null;
  refreshToken: string | null;
  userData: Record<string, any> | null;
  autoLogin: boolean | null;
  nextPath: string | null;
  isOrgSelected: boolean;
  setTokens: (accessToken: string, refreshToken: string | null) => void;
  setUserData: (user: Record<string, any> | null) => void;
  setAutoLogin: (value: boolean | null) => void;
  setNextPath: (path: string | null) => void;
  setIsOrgSelected: (value: boolean) => void;
  reset: () => void;
};

const useAuthStore = create<AuthState>((set) => ({
  isAuthenticated: false,
  accessToken: null,
  refreshToken: null,
  userData: null,
  autoLogin: null,
  nextPath: null,
  isOrgSelected: false,
  setTokens: (accessToken, refreshToken) =>
    set({ accessToken, refreshToken, isAuthenticated: !!accessToken }),
  setUserData: (user) => set({ userData: user }),
  setAutoLogin: (value) => set({ autoLogin: value }),
  setNextPath: (path) => set({ nextPath: path }),
  setIsOrgSelected: (value) => set({ isOrgSelected: value }),
  reset: () =>
    set({
      isAuthenticated: false,
      accessToken: null,
      refreshToken: null,
      userData: null,
      autoLogin: null,
      nextPath: null,
      isOrgSelected: false,
    }),
}));

async function requestJson(
  path: string,
  {
    method = "GET",
    headers = {},
    body,
    token,
    expectJson = true,
  }: {
    method?: string;
    headers?: Record<string, string>;
    body?: BodyInit | null;
    token?: string;
    expectJson?: boolean;
  } = {},
) {
  const finalHeaders: Record<string, string> = {
    Accept: "application/json",
    ...headers,
  };

  if (body && !(body instanceof FormData) && !headers["Content-Type"]) {
    finalHeaders["Content-Type"] =
      body instanceof URLSearchParams
        ? "application/x-www-form-urlencoded"
        : "application/json";
  }

  if (token) {
    finalHeaders["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(apiUrl(path), {
    method,
    headers: finalHeaders,
    body: body ?? undefined,
  });

  const text = expectJson ? await response.text() : null;
  const data = text ? (JSON.parse(text) as Record<string, any>) : null;

  if (!response.ok) {
    const detail = (data?.detail as string) ?? response.statusText;
    throw new HttpError(response.status, detail || "Request failed", data);
  }

  return data;
}

async function fetchWhoAmI(token: string) {
  return requestJson("users/whoami", { token });
}

async function ensureLangflowUser(
  token: string,
  username: string,
  maxRetries: number = 2,
): Promise<{ justCreated: boolean; user: Record<string, any> | null }> {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      const user = await fetchWhoAmI(token);
      return { justCreated: false, user };
    } catch (error) {
      if (error instanceof HttpError && error.status === 401) {
        try {
          await requestJson("users/", {
            method: "POST",
            token,
            body: JSON.stringify({
              username,
              password: CLERK_DUMMY_PASSWORD,
            }),
          });
          return { justCreated: true, user: null };
        } catch (createError) {
          if (
            createError instanceof HttpError &&
            createError.status === 400 &&
            typeof createError.data?.detail === "string" &&
            createError.data.detail.includes("username is unavailable")
          ) {
            await new Promise((resolve) => setTimeout(resolve, 100));
            continue;
          }
          throw createError;
        }
      }
      throw error;
    }
  }
  throw new Error("[ensureLangflowUser] Max retries exceeded");
}

async function backendLogin(username: string, token: string) {
  return requestJson("login", {
    method: "POST",
    token,
    body: new URLSearchParams({
      username,
      password: CLERK_DUMMY_PASSWORD,
    }),
  });
}

async function createOrganisation(token: string) {
  try {
    await requestJson("create_organisation", { method: "POST", token });
  } catch (error) {
    if (error instanceof HttpError && (error.status === 200 || error.status === 400)) {
      return;
    }
    throw error;
  }
}

function sanitizeRedirectPath(path: string | null) {
  if (!path) return null;
  try {
    const url = new URL(path, window.location.origin);
    return url.pathname + url.search + url.hash;
  } catch (_error) {
    return null;
  }
}

export default function NewLandingPageLogin() {
  const { isSignedIn, getToken } = useAuth();
  const { signOut } = useClerk();
  const { organization } = useOrganization();
  const { user } = useUser();
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [cookies, setCookie, removeCookie] = useCookies([
    LANGFLOW_ACCESS_TOKEN,
    LANGFLOW_REFRESH_TOKEN,
    LANGFLOW_AUTO_LOGIN_OPTION,
  ]);

  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [isBootstrapping, setIsBootstrapping] = useState(false);
  const bootstrappedRef = useRef(false);

  const setTokens = useAuthStore((state) => state.setTokens);
  const setUserData = useAuthStore((state) => state.setUserData);
  const setAutoLogin = useAuthStore((state) => state.setAutoLogin);
  const setNextPath = useAuthStore((state) => state.setNextPath);
  const setIsOrgSelected = useAuthStore((state) => state.setIsOrgSelected);
  const resetStore = useAuthStore((state) => state.reset);

  const redirectTarget = useMemo(() => {
    const params = new URLSearchParams(location.search);
    return sanitizeRedirectPath(params.get("redirect"));
  }, [location.search]);

  useEffect(() => {
    setNextPath(redirectTarget);
  }, [redirectTarget, setNextPath]);

  const persistSession = useCallback(
    (accessToken: string, refreshToken: string | null) => {
      const cookieOptions = { path: "/", sameSite: "lax" as const };
      setCookie(LANGFLOW_ACCESS_TOKEN, accessToken, cookieOptions);
      setCookie(LANGFLOW_AUTO_LOGIN_OPTION, "login", cookieOptions);
      if (refreshToken) {
        setCookie(LANGFLOW_REFRESH_TOKEN, refreshToken, cookieOptions);
      }
      setTokens(accessToken, refreshToken);
      setAutoLogin(false);
      setIsOrgSelected(true);
      sessionStorage.setItem("isOrgSelected", "true");
    },
    [setAutoLogin, setCookie, setIsOrgSelected, setTokens],
  );

  const clearSession = useCallback(async () => {
    removeCookie(LANGFLOW_ACCESS_TOKEN, { path: "/" });
    removeCookie(LANGFLOW_REFRESH_TOKEN, { path: "/" });
    removeCookie(LANGFLOW_AUTO_LOGIN_OPTION, { path: "/" });
    sessionStorage.removeItem("isOrgSelected");
    resetStore();
    try {
      await signOut();
    } catch (_error) {
      // ignore
    }
  }, [removeCookie, resetStore, signOut]);

  const redirectToApp = useCallback(() => {
    const target = useAuthStore.getState().nextPath ?? "/flows";
    window.location.href = target;
  }, []);

  const bootstrapSession = useCallback(async () => {
    if (!isSignedIn || !organization?.id || bootstrappedRef.current) {
      return;
    }
    setError(null);
    setStatus("Preparing your workspace...");
    setIsBootstrapping(true);
    bootstrappedRef.current = true;

    try {
      setStatus("Requesting Clerk token...");
      const orgToken = await getToken();
      if (!orgToken) {
        throw new Error("Unable to retrieve Clerk session token");
      }

      const username =
        user?.username ||
        user?.primaryEmailAddress?.emailAddress ||
        user?.id ||
        "clerk_user";

      setStatus("Ensuring organization exists...");
      await createOrganisation(orgToken);

      setStatus("Synchronizing user profile...");
      const { user: backendUser } = await ensureLangflowUser(orgToken, username);

      setStatus("Creating backend session...");
      const tokens = await backendLogin(username, orgToken);

      persistSession(orgToken, tokens?.refresh_token ?? null);
      if (backendUser) {
        setUserData(backendUser);
      } else {
        try {
          const whoami = await fetchWhoAmI(orgToken);
          setUserData(whoami);
        } catch (err) {
          console.warn("whoami failed after login", err);
        }
      }

      setStatus("Redirecting to Langflow...");
      redirectToApp();
    } catch (err) {
      console.error("Failed to bootstrap session", err);
      const message =
        err instanceof Error && err.message ? err.message : "Authentication failed";
      setError(message);
      bootstrappedRef.current = false;
      await clearSession();
    } finally {
      setIsBootstrapping(false);
      setStatus(null);
    }
  }, [
    clearSession,
    getToken,
    isSignedIn,
    organization?.id,
    persistSession,
    redirectToApp,
    setUserData,
    user,
  ]);

  useEffect(() => {
    if (!isSignedIn) {
      bootstrappedRef.current = false;
      return;
    }
    const selectedFlag = searchParams.get("selected") === "true";
    if (organization?.id && selectedFlag && !bootstrappedRef.current) {
      bootstrapSession();
    }
  }, [bootstrapSession, isSignedIn, organization?.id, searchParams]);

  const handleContinue = useCallback(() => {
    if (!isSignedIn || !organization?.id) {
      setError("Select or create an organization first");
      return;
    }
    bootstrapSession();
  }, [bootstrapSession, isSignedIn, organization?.id]);

  const displayName =
    user?.fullName ||
    user?.username ||
    user?.primaryEmailAddress?.emailAddress ||
    "Current member";
  const emailAddress =
    user?.primaryEmailAddress?.emailAddress || user?.emailAddresses?.[0]?.emailAddress || "";
  const avatarUrl = user?.imageUrl;
  const initials = displayName
    .split(" ")
    .map((segment) => segment[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  return (
    <div className="login-shell">
      <div className="login-grid">
        <section className="login-card login-card--primary">
          <p className="login-eyebrow">Secure access</p>
          <h1 className="login-heading">Sign in to Visual AI Agents Builder</h1>
          <p className="login-subheading">
            Use your Clerk identity to authenticate and seamlessly sync with Langflow's backend.
          </p>
          {error && (
            <div className="login-alert login-alert--error">
              <strong>Authentication error:</strong> {error}
            </div>
          )}
          {status && <div className="login-status">{status}</div>}
          <SignedOut>
            <SignIn
              path="/new-landingpage"
              routing="path"
              afterSignInUrl="/new-landingpage"
              redirectUrl="/new-landingpage"
            />
          </SignedOut>
          <SignedIn>
            <div className="login-alert login-alert--info">
              You're signed in with Clerk. Select an organization to finish logging in.
            </div>
          </SignedIn>
        </section>
        <section className="login-card">
          <div className="login-card-header">
            <div>
              <p className="login-eyebrow">Workspace selection</p>
              <h2 className="login-heading-small">Choose your organization</h2>
            </div>
            <button className="login-link" type="button" onClick={() => navigate("/")}>
              Back to landing
            </button>
          </div>
          <p className="login-subheading">
            Pick the Clerk organization you want to open in Langflow. We'll provision it automatically.
          </p>
          <SignedIn>
            <div className="login-user-summary">
              <div className="login-avatar">
                {avatarUrl ? <img src={avatarUrl} alt={displayName} /> : <span>{initials}</span>}
              </div>
              <div>
                <p className="login-user-name">{displayName}</p>
                <p className="login-user-email">{emailAddress}</p>
              </div>
            </div>
            <OrganizationList
              hidePersonal
              afterSelectOrganizationUrl="/new-landingpage?selected=true"
              afterCreateOrganizationUrl="/new-landingpage?selected=true"
            />
            <button
              type="button"
              className="login-button"
              onClick={handleContinue}
              disabled={isBootstrapping}
            >
              {isBootstrapping ? "Preparing workspace..." : "Continue to Langflow"}
            </button>
          </SignedIn>
          <SignedOut>
            <div className="login-alert login-alert--info">
              Sign in above to view your organizations.
            </div>
          </SignedOut>
        </section>
      </div>
    </div>
  );
}
