import { create } from "zustand";

interface ClerkConfigState {
  clerkAuthEnabled: boolean;
  clerkPublishableKey: string | null;
  clerkConfigLoaded: boolean; // Added new state
  setClerkConfig: (enabled: boolean, key: string | null) => void;
}

const useClerkConfigStore = create<ClerkConfigState>((set) => ({
  clerkAuthEnabled: false,
  clerkPublishableKey: null,
  clerkConfigLoaded: false, // Initialized to false
  setClerkConfig: (enabled, key) =>
    set({
      clerkAuthEnabled: enabled,
      clerkPublishableKey: key,
      clerkConfigLoaded: true, // Set to true on config set
    }),
}));

export default useClerkConfigStore;
