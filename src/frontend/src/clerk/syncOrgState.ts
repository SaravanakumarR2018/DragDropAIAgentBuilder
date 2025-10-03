import { useEffect } from "react";
import useAuthStore from "@/stores/authStore";

/**
 * Hook to sync Clerk organization state with local state
 */
export function useSyncClerkOrgState({
  isSignedIn,
  isOrgLoaded,
  orgId,
  isOrgSelected,
}: {
  isSignedIn: boolean;
  isOrgLoaded: boolean;
  orgId?: string;
  isOrgSelected: boolean;
}) {
  useEffect(() => {
    if (isSignedIn && isOrgLoaded && orgId && !isOrgSelected) {
      console.log("[useSyncClerkOrgState] Syncing Clerk org to local state");
      useAuthStore.getState().setIsOrgSelected(true);
      sessionStorage.setItem("isOrgSelected", "true");
    }
  }, [isSignedIn, isOrgLoaded, orgId, isOrgSelected]);
}
