import { IS_CLERK_AUTH } from "@/clerk/auth";
import { CustomNavigate } from "@/customization/components/custom-navigate";
import useAuthStore from "@/stores/authStore";
import Landing from "../LandingPage";

export function PublicLandingPage() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const autoLogin = useAuthStore((state) => state.autoLogin);

  if (isAuthenticated || autoLogin) {
    return (
      <CustomNavigate
        replace
        to={IS_CLERK_AUTH ? "/organization" : "/flows"}
      />
    );
  }

  return <Landing />;
}

export default PublicLandingPage;
