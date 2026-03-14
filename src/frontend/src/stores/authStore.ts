// authStore.js

import { create } from "zustand";
import { clearStoredActiveOrgId } from "@/clerk/activeOrgStorage";
import {
  LANGFLOW_ACCESS_TOKEN,
  LANGFLOW_API_TOKEN,
  LANGFLOW_REFRESH_TOKEN,
} from "@/constants/constants";
import type { AuthStoreType } from "@/types/zustand/auth";
import { cookieManager, getCookiesInstance } from "@/utils/cookie-manager";

const useAuthStore = create<AuthStoreType>((set, get) => ({
  isAdmin: false,
  // Authentication state is now determined by session validation, not cookie reads
  // This allows HttpOnly cookies to work properly
  isAuthenticated: false,
  accessToken: null,
  userData: null,
  autoLogin: null,
  apiKey: null,
  authenticationErrorCount: 0,
  isOrgSelected: (() => {
    try {
      // Dynamically import IS_CLERK_AUTH to avoid circular deps
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { IS_CLERK_AUTH } = require("@/clerk/auth");
      return IS_CLERK_AUTH ? false : undefined;
    } catch {
      return undefined;
    }
  })(),

  setIsAdmin: (isAdmin) => set({ isAdmin }),
  setIsAuthenticated: (isAuthenticated) => set({ isAuthenticated }),
  setAccessToken: (accessToken) => set({ accessToken }),
  setUserData: (userData) => set({ userData }),
  setAutoLogin: (autoLogin) => set({ autoLogin }),
  setApiKey: (apiKey) => set({ apiKey }),
  setAuthenticationErrorCount: (authenticationErrorCount) =>
    set({ authenticationErrorCount }),
  setIsOrgSelected: (isOrgSelected) => set({ isOrgSelected }),

logout: async () => {
  sessionStorage.removeItem("isOrgSelected");
  clearStoredActiveOrgId();
  get().setIsAuthenticated(false);
  get().setIsAdmin(false);
  get().setIsOrgSelected(false);

  set({
    isAdmin: false,
    userData: null,
    accessToken: null,
    isAuthenticated: false,
    autoLogin: false,
    apiKey: null,
    isOrgSelected: false,
  });
},

}));

export default useAuthStore;
