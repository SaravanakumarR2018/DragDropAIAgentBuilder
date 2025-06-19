import {
  IS_AUTO_LOGIN,
  LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS,
  LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS_ENV,
  LANGFLOW_AUTO_LOGIN_OPTION // Added import
} from "@/constants/constants";
// TODO: Ensure @clerk/clerk-react is installed
import { useAuth } from "@clerk/clerk-react";
import { useRefreshAccessToken } from "@/controllers/API/queries/auth";
import useAuthStore from "@/stores/authStore";
import useClerkConfigStore from "@/stores/clerkConfigStore";
import { useEffect } from "react";
import { Cookies } from "react-cookie"; // Added import
import { Navigate, useLocation } from "react-router-dom"; // Added imports
import { LoadingPage } from "@/pages/LoadingPage";

export const ProtectedRoute = ({ children }) => {
  const location = useLocation();
  const { isAuthenticated, autoLogin: autoLoginState } = useAuthStore();
  const { clerkAuthEnabled, clerkConfigLoaded } = useClerkConfigStore(); // Get clerkConfigLoaded

  // Conditionally call useAuth to prevent errors if ClerkProvider is not yet in the tree
  const clerkAuthHookResult = (clerkConfigLoaded && clerkAuthEnabled)
    ? useAuth()
    : { isLoaded: false, isSignedIn: false };
  const { isLoaded: clerkIsLoaded, isSignedIn: clerkIsSignedIn } = clerkAuthHookResult;

  const cookies = new Cookies();
  const autoLoginCookie = cookies.get(LANGFLOW_AUTO_LOGIN_OPTION);
  const { mutate: mutateRefresh } = useRefreshAccessToken();

  const testMockAutoLogin = sessionStorage.getItem("testMockAutoLogin");

  // Priority 1: If Langflow (native) authentication is established
  if (isAuthenticated) {
    return children;
  }

  // Priority 2: Clerk Authentication (if enabled via config and no existing Langflow session)
  if (clerkAuthEnabled) {
    if (!clerkConfigLoaded) {
      // Waiting for Clerk config to be loaded from backend (e.g. publishable key)
      return <LoadingPage />;
    }
    // At this point, config IS loaded, and Clerk is the chosen auth method.
    // Now rely on Clerk's own loading state.
    if (!clerkIsLoaded) {
      // Clerk SDK itself is loading (e.g., checking session with Clerk servers)
      return <LoadingPage />;
    }
    if (clerkIsSignedIn) {
      // User is signed in with Clerk. AuthContext should handle setting isAuthenticated.
      return children;
    }
    // Clerk is loaded, but user is not signed in. Redirect to Clerk's login.
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Priority 3: Native Langflow Login Path
  // (Clerk is disabled, or Clerk config is loaded but clerkAuthEnabled is false)
  // And Langflow session is not authenticated (checked by Priority 1)

  // The useEffect for native token refresh was here. As discussed,
  // interval-based refresh for an *active* session belongs in AuthContext.
  // For an *unauthenticated* user hitting a protected route, the main goal is
  // to redirect to login or show loading if an auto-login attempt is pending.
  useEffect(() => {
    // This effect might be reconsidered or simplified.
    // If !isAuthenticated and !clerkAuthEnabled, the logic below handles redirection.
    // No active token refresh should happen here for an unauthenticated user.
  }, [clerkAuthEnabled, isAuthenticated, autoLoginState, mutateRefresh, autoLoginCookie]);

  if (testMockAutoLogin) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // This block executes if:
  // 1. Native `isAuthenticated` is false (Priority 1 check failed)
  // 2. AND (`clerkAuthEnabled` is false OR (`clerkAuthEnabled` is true BUT `clerkConfigLoaded` is false - covered by loading above))
  // Essentially, this is the path if Clerk is not the active and ready auth method.
  if (!isAuthenticated) { // Re-check isAuthenticated as it's the definitive native flag
    if (clerkConfigLoaded && !clerkAuthEnabled) { // Config loaded, Clerk definitively disabled
      if (autoLoginCookie) {
        return <LoadingPage />; // Waiting for native auto-login to resolve
      }
      return <Navigate to="/login" state={{ from: location }} replace />; // No auto-login, redirect to native
    } else if (!clerkConfigLoaded && autoLoginCookie) {
      // Config not loaded yet, but an autoLoginCookie exists (could be native). Show loading.
      // This state implies we don't know yet if Clerk will be enabled.
      return <LoadingPage />;
    } else if (!clerkConfigLoaded && !autoLoginCookie) {
      // Config not loaded, no autoLoginCookie. This is an ambiguous state.
      // It might be initial load. Showing LoadingPage is safest.
      // AppInitPage should eventually set clerkConfigLoaded.
      return <LoadingPage />;
    }
  }

  // Fallback: Should ideally not be reached if logic above is comprehensive.
  // Covers transitions or unexpected states.
  return <LoadingPage />;
};
