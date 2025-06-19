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
  const clerkAuthEnabled = useClerkConfigStore((state) => state.clerkAuthEnabled);
  const { isLoaded, isSignedIn, sessionId, getToken } = useAuth();
  const { user: clerkUser } = useUser();
  const { signOut: clerkSignOut } = useClerk();


  // Effect to initialize accessToken from cookies if Clerk is not enabled
  useEffect(() => {
    if (!clerkAuthEnabled) {
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
    if (clerkAuthEnabled && isSignedIn && getToken) {
      const fetchToken = async () => {
        try {
          // TODO: Potentially use a template here from Clerk dashboard for backend authentication
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
    } else if (clerkAuthEnabled && !isSignedIn) {
      setAccessToken(null);
      setIsAuthenticated(false);
    }
  }, [clerkAuthEnabled, isSignedIn, getToken, setIsAuthenticated, sessionId]);


  // Effect to initialize apiKey from cookies (applies to both modes)
  useEffect(() => {
    const storedApiKey = cookies.get(LANGFLOW_API_TOKEN);
    if (storedApiKey) {
      setApiKey(storedApiKey);
    }
  }, [cookies]);


  const getUser = useCallback(() => {
    if (clerkAuthEnabled) {
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
    } else {
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
    // For native auth, trigger if accessToken is present (set from cookie)
    // For Clerk auth, trigger if isSignedIn and clerkUser are available
    if (!clerkAuthEnabled && accessToken && !userData) { // Only if native auth, token exists, but no user data yet
      getUser();
    } else if (clerkAuthEnabled && isSignedIn && clerkUser && !userData) { // Clerk signed in, user data available, but not yet set in context
       getUser();
    } else if (clerkAuthEnabled && !isSignedIn) { // Clerk signed out
      setUserData(null);
    }
   }, [clerkAuthEnabled, accessToken, isSignedIn, clerkUser, getUser, userData]);


  const login = useCallback(
    (newAccessToken: string, autoLogin: string, refreshToken?: string) => {
      if (clerkAuthEnabled) {
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
    [clerkAuthEnabled, cookies, setIsAuthenticated, getUser, getGlobalVariables], // Added getGlobalVariables
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
    if (clerkAuthEnabled) {
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
  }, [clerkAuthEnabled, clerkSignOut, cookies, navigate, setIsAuthenticated]);


  // This effect ensures that if the native isAuthenticated state changes (e.g. due to cookie expiry not handled elsewhere)
  // or clerk's isSignedIn changes, the UI reflects it.
  // This is particularly for the case where Clerk is not enabled.
  useEffect(() => {
    if (!clerkAuthEnabled && !nativeIsAuthenticated && accessToken) {
      // If native token expired or was removed, but state still thinks it's auth'd
      setAccessToken(null);
      setUserData(null);
    }
  }, [clerkAuthEnabled, nativeIsAuthenticated, accessToken]);


  // Initial check for user data if already authenticated (e.g. page refresh)
  // This needs to be handled carefully with clerk's isLoaded
  useEffect(() => {
    if (clerkAuthEnabled) {
      if (isLoaded && isSignedIn && !userData) {
        getUser();
      }
    } else {
      if (cookies.get(LANGFLOW_ACCESS_TOKEN) && !userData && !accessToken) {
        // If native token exists in cookie, but not in state yet (e.g. initial load)
        // The accessToken effect should handle setting it, then the getUser effect will trigger.
      } else if (accessToken && !userData) {
        getUser(); // If accessToken is set (from cookie or login) but no user data
      }
    }
  }, [clerkAuthEnabled, isLoaded, isSignedIn, userData, accessToken, cookies, getUser]);


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
