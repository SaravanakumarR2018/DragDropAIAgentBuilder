import { CustomNavigate } from "@/customization/components/custom-navigate";
import useAuthStore from "@/stores/authStore";
import { Navigate } from "react-router-dom";

/**
 * CatchAllRedirect component handles unknown/invalid routes by redirecting based on authentication status.
 * 
 * Authenticated users: Redirects to /app/flows (main workspace)
 * Unauthenticated users: Redirects to / (landing page)
 */
export function CatchAllRedirect() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const autoLogin = useAuthStore((state) => state.autoLogin);

  // Determine if user is truly authenticated (either logged in or auto-login enabled)
  const isUserAuthenticated = isAuthenticated || autoLogin === true;

  if (!isUserAuthenticated) {
    return <Navigate replace to="/" />;
  }

  return <CustomNavigate replace to="/app/flows" />;
}
