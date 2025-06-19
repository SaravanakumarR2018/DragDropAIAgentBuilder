import { create } from "zustand";

interface ClerkConfigState {
  clerkAuthEnabled: boolean;
  clerkPublishableKey: string | null;
  setClerkConfig: (enabled: boolean, key: string | null) => void;
}

const useClerkConfigStore = create<ClerkConfigState>((set) => ({
  clerkAuthEnabled: false,
  clerkPublishableKey: null,
  setClerkConfig: (enabled, key) => set({ clerkAuthEnabled: enabled, clerkPublishableKey: key }),
}));

export default useClerkConfigStore;
