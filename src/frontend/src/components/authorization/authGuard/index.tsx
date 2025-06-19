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
  const { isAuthenticated, autoLogin: autoLoginState } = useAuthStore(); // Renamed autoLogin to avoid conflict with variable name
  const clerkAuthEnabled = useClerkConfigStore((state) => state.clerkAuthEnabled);
  const { isLoaded: clerkIsLoaded, isSignedIn: clerkIsSignedIn } = useAuth();
  const cookies = new Cookies();
  const autoLoginCookie = cookies.get(LANGFLOW_AUTO_LOGIN_OPTION);
  const { mutate: mutateRefresh } = useRefreshAccessToken(); // For native token refresh

  // This test mock seems specific and might need to be re-evaluated or integrated differently
  // For now, if it exists, it forces a redirect similar to shouldRedirect.
  const testMockAutoLogin = sessionStorage.getItem("testMockAutoLogin");


  // Priority 1: If Langflow authentication is established (e.g., via auto-login or previous session)
  if (isAuthenticated) {
    return children;
  }

  // Priority 2: Clerk Authentication (if enabled and no existing Langflow session)
  if (clerkAuthEnabled) {
    if (!clerkIsLoaded) {
      // Clerk SDK is loading its state
      return <LoadingPage />;
    }
    if (clerkIsSignedIn) {
      // User is signed in with Clerk
      // At this point, AuthContext should sync Langflow's isAuthenticated
      // For now, assuming children implies authenticated state is being handled by AuthContext sync
      return children;
    }
    // User is not signed in with Clerk, redirect to Clerk's login page
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Priority 3: Native Langflow Login Path (Clerk is disabled and Langflow session not authenticated)
  // This is where the native token refresh logic comes into play.
  // The useEffect for token refresh should be here.
  useEffect(() => {
    if (!clerkAuthEnabled && !isAuthenticated && !autoLoginCookie) {
      // Only attempt refresh if not using clerk, not already auth'd,
      // and not in an explicit auto-login flow (autoLoginCookie might indicate this)
      // However, typical token refresh is for an existing session.
      // This original logic for interval refresh might be better suited inside AuthContext
      // or when a user is already authenticated.
      // For an unauthenticated user hitting a protected route, we usually redirect or check auto-login.
      // The original logic: `if (autoLoginState !== undefined && !autoLoginState && isAuthenticated)`
      // was for refreshing an already active non-auto-login session.
      // Let's refine this: if we're here, user is NOT authenticated.
      // We should check if an auto-login attempt is expected (via autoLoginCookie).
      // If not, direct to login. If auto-login is expected, show loading.
      // The token refresh logic from before was for *maintaining* a session.
      // Here, we are trying to *establish* one or redirect.
      // For now, removing the interval refresh from here as it doesn't fit the unauthenticated flow.
      // It should be in AuthContext for an active session.
    }
  }, [clerkAuthEnabled, isAuthenticated, autoLoginState, mutateRefresh, autoLoginCookie]);


  // If testMockAutoLogin exists, it forces a redirect (mimicking failed auth)
  if (testMockAutoLogin) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // If Clerk is disabled, and user is not authenticated:
  if (!clerkAuthEnabled && !isAuthenticated) {
    // If autoLoginCookie exists, it implies AppInitPage's useGetAutoLogin is (or was) pending.
    // AuthContext should handle setting isAuthenticated if auto-login succeeds.
    // If it fails, AppInitPage/AuthContext should clear the autoLoginCookie.
    if (autoLoginCookie) {
      // We are likely waiting for auto-login to resolve.
      // AuthContext will update isAuthenticated, which will re-evaluate ProtectedRoute.
      return <LoadingPage />;
    }
    // No auto-login cookie, and not authenticated: redirect to native login.
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Fallback/Default: Should ideally be covered by other conditions.
  // This might be hit if clerkAuthEnabled is true but clerk is not loaded yet,
  // or if native auto-login is resolving.
  return <LoadingPage />;
};
