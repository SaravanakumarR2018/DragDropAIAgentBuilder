import { CustomNavigate } from "@/customization/components/custom-navigate";
import useAuthStore from "@/stores/authStore";
import { useOrganization } from "@clerk/clerk-react";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import { useLocation } from "react-router-dom";

export const ProtectedLoginRoute = ({ children }) => {
  const autoLogin = useAuthStore((state) => state.autoLogin);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const location = useLocation();

  let organizationId: string | undefined = undefined;
  let isOrgLoaded = true;

  if (IS_CLERK_AUTH) {
    const { organization, isLoaded } = useOrganization();
    organizationId = organization?.id;
    isOrgLoaded = isLoaded;
  }

  const isLoginPage = location.pathname.includes("login");
  if (!isLoginPage) return children;

  const isOrgSelected = IS_CLERK_AUTH ? !!organizationId : true;

  const canRedirect =
    isOrgLoaded &&
    (autoLogin === true || isAuthenticated) &&
    isOrgSelected;

  if (canRedirect) {
    const urlParams = new URLSearchParams(window.location.search);
    const redirectPath = urlParams.get("redirect");

    if (redirectPath) {
      return <CustomNavigate to={redirectPath} replace />;
    }
    return <CustomNavigate to="/flows" replace />;
  }
  return children;
};
