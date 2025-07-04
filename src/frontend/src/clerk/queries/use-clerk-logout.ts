import { clerkClient } from "@clerk/clerk-react";
import useAuthStore from "@/stores/authStore";

export const useClerkLogout = () => async () => {
  await clerkClient.signOut();
  useAuthStore.getState().logout();
};
