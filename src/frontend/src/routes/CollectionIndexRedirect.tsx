import { IS_CLERK_AUTH } from "@/clerk/auth";
import { CustomNavigate } from "@/customization/components/custom-navigate";
import authStore from "@/stores/authStore";

const isOrganizationSelected = () => {
  if (authStore.getState().isOrgSelected) {
    return true;
  }

  if (typeof window !== "undefined") {
    return sessionStorage.getItem("isOrgSelected") === "true";
  }

  return false;
};

export function CollectionIndexRedirect() {
  const { isAuthenticated } = authStore.getState();

  if (IS_CLERK_AUTH && isAuthenticated && !isOrganizationSelected()) {
    return <CustomNavigate replace to="/organization" />;
  }

  return <CustomNavigate replace to="flows" />;
}
