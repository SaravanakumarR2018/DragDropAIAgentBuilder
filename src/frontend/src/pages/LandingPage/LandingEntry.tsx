import { IS_CLERK_AUTH } from "@/clerk/auth";
import { CustomNavigate } from "@/customization/components/custom-navigate";
import useAuthStore from "@/stores/authStore";

import Landing from ".";

export function LandingEntry() {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  if (isAuthenticated) {
    return (
      <CustomNavigate
        replace
        to={IS_CLERK_AUTH ? "/organization" : "flows"}
      />
    );
  }

  return <Landing />;
}

export default LandingEntry;
