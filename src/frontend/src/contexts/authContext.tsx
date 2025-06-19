import {
  LANGFLOW_ACCESS_TOKEN,
  LANGFLOW_API_TOKEN,
  LANGFLOW_AUTO_LOGIN_OPTION,
  LANGFLOW_REFRESH_TOKEN,
// TODO: Ensure @clerk/clerk-react is installed
import { useAuth, useUser, useClerk } from "@clerk/clerk-react"; // Updated imports
} from "@/constants/constants";
import { useGetUserData } from "@/controllers/API/queries/auth";
import { useGetGlobalVariablesMutation } from "@/controllers/API/queries/variables/use-get-mutation-global-variables";
import useAuthStore from "@/stores/authStore";
import useClerkConfigStore from "../stores/clerkConfigStore";
import { setLocalStorage } from "@/utils/local-storage-util";
import { createContext, useEffect, useState, useCallback } from "react"; // Added useCallback
import { Cookies } from "react-cookie";
import { useNavigate } from "react-router-dom"; // Added useNavigate
import { useStoreStore } from "../stores/storeStore";
import { Users } from "../types/api";
import { AuthContextType } from "../types/contexts/auth";

const initialValue: AuthContextType = {
  accessToken: null,
  login: () => {},
  userData: null,
  setUserData: () => {},
  authenticationErrorCount: 0,
  setApiKey: () => {},
  apiKey: null,
  storeApiKey: () => {},
  getUser: () => {},
  logout: async () => {}, // Added logout to initialValue
};

export const AuthContext = createContext<AuthContextType>(initialValue);

export function AuthProvider({ children }): React.ReactElement {
  const cookies = new Cookies();
  const navigate = useNavigate(); // For logout redirection

  // Native state
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const [userData, setUserData] = useState<Users | null>(null);
  const [apiKey, setApiKey] = useState<string | null>(null);

  // Zustand stores
  const checkHasStore = useStoreStore((state) => state.checkHasStore);
  const fetchApiData = useStoreStore((state) => state.fetchApiData);
  const setIsAuthenticated = useAuthStore((state) => state.setIsAuthenticated);
  const nativeIsAuthenticated = useAuthStore((state) => state.isAuthenticated);


  // API mutations
  const { mutate: mutateLoggedUser } = useGetUserData();
  const { mutate: mutateGetGlobalVariables } = useGetGlobalVariablesMutation();

  // Clerk related state and hooks
  const { clerkAuthEnabled, clerkConfigLoaded } = useClerkConfigStore(); // Get clerkConfigLoaded

  // Conditionally call Clerk hooks only if config is loaded and Clerk is enabled
  const clerkAuthState = (clerkConfigLoaded && clerkAuthEnabled)
    ? useAuth()
    : { isLoaded: false, isSignedIn: false, sessionId: null, getToken: async () => null };
  const { isLoaded, isSignedIn, sessionId, getToken } = clerkAuthState;

  const clerkUserState = (clerkConfigLoaded && clerkAuthEnabled)
    ? useUser()
    : { user: null };
  const { user: clerkUser } = clerkUserState;

  const clerkInstance = (clerkConfigLoaded && clerkAuthEnabled)
    ? useClerk()
    : { signOut: async () => {} };
  const { signOut: clerkSignOut } = clerkInstance;


  // Effect to initialize accessToken from cookies if Clerk is not enabled
  useEffect(() => {
    if (clerkConfigLoaded && !clerkAuthEnabled) { // Ensure config is loaded before deciding native path
      const storedAccessToken = cookies.get(LANGFLOW_ACCESS_TOKEN);
      if (storedAccessToken) {
        setAccessToken(storedAccessToken);
        setIsAuthenticated(true); // Assume authenticated if token exists
        // Potentially call getUser here if not handled by another effect
      } else {
        setIsAuthenticated(false);
      }
    }
  }, [clerkAuthEnabled, cookies, setIsAuthenticated]);

  // Effect to set accessToken from Clerk token
  useEffect(() => {
    if (clerkConfigLoaded && clerkAuthEnabled && isSignedIn && getToken) { // Check clerkConfigLoaded
      const fetchToken = async () => {
        try {
          const clerkToken = await getToken();
          setAccessToken(clerkToken ?? null);
          setIsAuthenticated(true);
        } catch (error) {
          console.error("Error fetching Clerk token:", error);
          setAccessToken(null);
          setIsAuthenticated(false);
        }
      };
      fetchToken();
    } else if (clerkConfigLoaded && clerkAuthEnabled && !isSignedIn) { // Check clerkConfigLoaded
      setAccessToken(null);
      setIsAuthenticated(false);
    }
  }, [clerkConfigLoaded, clerkAuthEnabled, isSignedIn, getToken, setIsAuthenticated, sessionId]); // Added clerkConfigLoaded


  // Effect to initialize apiKey from cookies (applies to both modes)
  useEffect(() => {
    const storedApiKey = cookies.get(LANGFLOW_API_TOKEN);
    if (storedApiKey) {
      setApiKey(storedApiKey);
    }
  }, [cookies]);


  const getUser = useCallback(() => {
    if (clerkConfigLoaded && clerkAuthEnabled) { // Check clerkConfigLoaded
      if (isSignedIn && clerkUser) {
        const langflowUser: Users = {
          id: clerkUser.id,
          username: clerkUser.username ?? clerkUser.primaryEmailAddress?.emailAddress ?? "",
          email: clerkUser.primaryEmailAddress?.emailAddress,
          profile_image_url: clerkUser.imageUrl,
          is_active: clerkUser.unsafeMetadata?.is_active ?? true, // Assuming active, or use custom metadata
          is_superuser: clerkUser.unsafeMetadata?.is_superuser ?? false, // Requires custom metadata in Clerk
          create_at: clerkUser.createdAt ? clerkUser.createdAt.toISOString() : new Date().toISOString(),
          updated_at: clerkUser.updatedAt ? clerkUser.updatedAt.toISOString() : new Date().toISOString(),
          // Other fields like components_permission, flows_permission, prompt_permission might need separate handling
          // or default values if not available directly from Clerk.
        };
        setUserData(langflowUser);
        useAuthStore.getState().setIsAdmin(langflowUser.is_superuser ?? false);
        setIsAuthenticated(true); // Ensure this is set
        // These might still be relevant depending on app logic
        checkHasStore();
        fetchApiData();
      } else {
        setUserData(null); // Clear user data if not signed in via Clerk
        // setIsAuthenticated(false); // Handled by accessToken effect
      }
    } else if (clerkConfigLoaded && !clerkAuthEnabled) { // Ensure config is loaded before deciding native path
      // Native Langflow user fetching
      mutateLoggedUser(
        {},
        {
          onSuccess: async (user) => {
            setUserData(user);
            const isSuperUser = user!.is_superuser;
            useAuthStore.getState().setIsAdmin(isSuperUser);
            setIsAuthenticated(true);
            checkHasStore();
            fetchApiData();
          },
          onError: () => {
            setUserData(null);
            setIsAuthenticated(false);
          },
        },
      );
    }
  }, [clerkAuthEnabled, isSignedIn, clerkUser, mutateLoggedUser, setIsAuthenticated, checkHasStore, fetchApiData]);

  // Effect to call getUser when authentication state changes
   useEffect(() => {
    if (clerkConfigLoaded && !clerkAuthEnabled && accessToken && !userData) {
      getUser();
    } else if (clerkConfigLoaded && clerkAuthEnabled && isSignedIn && clerkUser && !userData) {
       getUser();
    } else if (clerkConfigLoaded && clerkAuthEnabled && !isSignedIn) {
      setUserData(null);
    }
   }, [clerkConfigLoaded, clerkAuthEnabled, accessToken, isSignedIn, clerkUser, getUser, userData]); // Added clerkConfigLoaded


  const login = useCallback(
    (newAccessToken: string, autoLogin: string, refreshToken?: string) => {
      // This function should only be called if Clerk is disabled or config not loaded yet (though latter is less likely)
      if (clerkConfigLoaded && clerkAuthEnabled) {
        console.warn(
          "Native login function called while Clerk authentication is enabled. Please use Clerk's <SignIn /> component.",
        );
        return;
      }
      // Native login logic
      cookies.set(LANGFLOW_ACCESS_TOKEN, newAccessToken, { path: "/" });
      cookies.set(LANGFLOW_AUTO_LOGIN_OPTION, autoLogin, { path: "/" });
      setLocalStorage(LANGFLOW_ACCESS_TOKEN, newAccessToken);

      if (refreshToken) {
        cookies.set(LANGFLOW_REFRESH_TOKEN, refreshToken, { path: "/" });
      }
      setAccessToken(newAccessToken);
      setIsAuthenticated(true);
      getUser(); // Fetch user data after native login
      getGlobalVariables();
    },
    [clerkConfigLoaded, clerkAuthEnabled, cookies, setIsAuthenticated, getUser, getGlobalVariables], // Added clerkConfigLoaded
  );

  const storeApiKey = useCallback((newApiKey: string) => {
    setApiKey(newApiKey);
    // Optionally, save to cookies if needed for persistence across sessions, though API keys are often session-based
    // cookies.set(LANGFLOW_API_TOKEN, newApiKey, { path: "/" });
  }, []);


  const getGlobalVariables = useCallback(() => {
    mutateGetGlobalVariables({});
  }, [mutateGetGlobalVariables]);

  const logout = useCallback(async () => {
    if (clerkConfigLoaded && clerkAuthEnabled) { // Check clerkConfigLoaded
      try {
        await clerkSignOut();
      } catch (error) {
        console.error("Error signing out from Clerk:", error);
      }
    }
    // Clear Langflow specific cookies and state
    cookies.remove(LANGFLOW_ACCESS_TOKEN, { path: "/" });
    cookies.remove(LANGFLOW_REFRESH_TOKEN, { path: "/" });
    cookies.remove(LANGFLOW_AUTO_LOGIN_OPTION, { path: "/" });
    // LANGFLOW_API_TOKEN is not session specific usually, but if you want to clear it on logout:
    // cookies.remove(LANGFLOW_API_TOKEN, { path: "/" });
    // setApiKey(null);

    setAccessToken(null);
    setUserData(null);
    setIsAuthenticated(false);
    useAuthStore.getState().setIsAdmin(false); // Reset admin status

    navigate("/login");
  }, [clerkConfigLoaded, clerkAuthEnabled, clerkSignOut, cookies, navigate, setIsAuthenticated]); // Added clerkConfigLoaded


  // This effect ensures that if the native isAuthenticated state changes (e.g. due to cookie expiry not handled elsewhere)
  // or clerk's isSignedIn changes, the UI reflects it.
  useEffect(() => {
    if (clerkConfigLoaded && !clerkAuthEnabled && !nativeIsAuthenticated && accessToken) { // Check clerkConfigLoaded
      // If native token expired or was removed, but state still thinks it's auth'd
      setAccessToken(null);
      setUserData(null);
    }
  }, [clerkConfigLoaded, clerkAuthEnabled, nativeIsAuthenticated, accessToken]); // Added clerkConfigLoaded


  // Initial check for user data if already authenticated (e.g. page refresh)
  useEffect(() => {
    if (clerkConfigLoaded && clerkAuthEnabled) { // Check clerkConfigLoaded
      if (isLoaded && isSignedIn && !userData) {
        getUser();
      }
    } else if (clerkConfigLoaded && !clerkAuthEnabled) { // Check clerkConfigLoaded before native logic
      if (cookies.get(LANGFLOW_ACCESS_TOKEN) && !userData && !accessToken) {
        // Native token exists in cookie, but not in state yet (initial load)
        // The accessToken effect (for native) should handle setting it, then the getUser effect will trigger.
      } else if (accessToken && !userData) {
        getUser(); // If accessToken is set (from cookie or login) but no user data
      }
    }
    // If clerkConfigLoaded is false, we wait for config to load. AppInitPage handles initial loading.
  }, [clerkConfigLoaded, clerkAuthEnabled, isLoaded, isSignedIn, userData, accessToken, cookies, getUser]); // Added clerkConfigLoaded


  return (
    <AuthContext.Provider
      value={{
        accessToken,
        login,
        setUserData,
        userData,
        authenticationErrorCount: 0,
        setApiKey,
        apiKey,
        storeApiKey,
        getUser,
        logout, // Added logout
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
