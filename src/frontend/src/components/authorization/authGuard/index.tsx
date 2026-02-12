import {
  IS_AUTO_LOGIN,
  LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS,
  LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS_ENV,
} from "@/constants/constants";
import { api } from "@/controllers/API/api";
import { useRefreshAccessToken } from "@/controllers/API/queries/auth";
import { CustomNavigate } from "@/customization/components/custom-navigate";
import useAuthStore from "@/stores/authStore";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { useOrganization, useAuth as useClerkAuth } from "@clerk/clerk-react";

export const ProtectedRoute = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const autoLogin = useAuthStore((state) => state.autoLogin);
  const isOrgSelectedStore = useAuthStore((state) => state.isOrgSelected);
  const isOrgSelected =
    isOrgSelectedStore ||
    sessionStorage.getItem("isOrgSelected") === "true";
  const { mutate: mutateRefresh } = useRefreshAccessToken();
  const testMockAutoLogin = sessionStorage.getItem("testMockAutoLogin");
  const [isCheckingFlowsAccess, setIsCheckingFlowsAccess] = useState(false);
  const [hasFlowsAccess, setHasFlowsAccess] = useState<boolean | null>(null);

  // Clerk values
  const { organization, isLoaded: isOrgLoaded } = useOrganization();
  const { isSignedIn, getToken } = useClerkAuth();
  const orgId = organization?.id;

  
  // Get current path
  const location = useLocation();
  const currentPath = location.pathname;
  const isLoginPage = currentPath.includes("login");
  const isOrgPage = currentPath.includes("organization");
  const isAdminPage = currentPath.includes("/admin");
  const isRootPage = currentPath === "/";
  const isFlowsPage = currentPath.includes("/flows");
  const isPricingPage = currentPath.includes("/pricing");

  useEffect(() => {
    if (!isFlowsPage || !isOrgLoaded || !isSignedIn || !isOrgSelected) {
      setIsCheckingFlowsAccess(false);
      setHasFlowsAccess(null);
      return;
    }

    let active = true;
    setIsCheckingFlowsAccess(true);

    (async () => {
      try {
        const orgToken = await getToken();
        if (!orgToken) {
          if (active) {
            setHasFlowsAccess(false);
          }
          return;
        }

        const response = await api.get("billing/org-access", {
          headers: { Authorization: `Bearer ${orgToken}` },
        });
        const denied = response?.data?.redirect_to === "/pricing";

        if (active) {
          setHasFlowsAccess(!denied);
        }
      } catch (_error) {
        if (active) {
          setHasFlowsAccess(false);
        }
      } finally {
        if (active) {
          setIsCheckingFlowsAccess(false);
        }
      }
    })();

    return () => {
      active = false;
    };
  }, [getToken, isFlowsPage, isOrgLoaded, isOrgSelected, isSignedIn]);

  // ✅ Root path "/" is PUBLIC - don't redirect unauthenticated users
  if (isRootPage) {
    return children;
  }

  // ✅ Pricing page requires a signed-in Clerk user + selected organization,
  // but does not require backend session cookies yet.
  if (isPricingPage) {
    if (!isOrgLoaded || autoLogin === undefined) {
      return null;
    }

    if (!isSignedIn || testMockAutoLogin) {
      return <CustomNavigate to="/login?redirect=/pricing" replace />;
    }

    if (!isOrgSelected) {
      return <CustomNavigate to="/organization" replace />;
    }

    return children;
  }

  if (isFlowsPage && isCheckingFlowsAccess) {
    return null;
  }

  if (isFlowsPage && hasFlowsAccess === false) {
    return <CustomNavigate to="/pricing" replace />;
  }


  // If Clerk user has org context but backend session is not ready yet,
  // keep them on pricing instead of forcing login/logout loops from /flows.
  const shouldRedirectFlowsToPricing =
    isOrgLoaded &&
    isFlowsPage &&
    isSignedIn &&
    isOrgSelected &&
    !isAuthenticated;

  if (shouldRedirectFlowsToPricing) {
    return <CustomNavigate to="/pricing" replace />;
  }

  // 1️⃣ Redirect to login if not authenticated (for protected pages only)
  const shouldRedirectToLogin =
    isOrgLoaded &&
    (!isAuthenticated || !isSignedIn) &&
    autoLogin !== undefined &&
    (!autoLogin || !IS_AUTO_LOGIN);

  // 2️⃣ Redirect to organization selection if signed in but no org yet
  const shouldRedirectToOrg =
    isOrgLoaded &&
    isAuthenticated &&
    isSignedIn &&
    !isOrgSelected &&
    !isOrgPage &&
    !isAdminPage &&
    !isLoginPage;

  // ✅ 3️⃣ DO NOT redirect "/" to "/flows" - authenticated users should stay on landing page
  const shouldRedirectHome = false;

  // 🔄 Setup token refresh
  useEffect(() => {
    const refreshTime = isNaN(LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS_ENV)
      ? LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS
      : LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS_ENV;

    if (autoLogin !== undefined && !autoLogin && isAuthenticated) {
      const intervalId = setInterval(() => {
        mutateRefresh();
      }, refreshTime * 1000);

      return () => {
        clearInterval(intervalId);
      };
    }
  }, [isAuthenticated, autoLogin, mutateRefresh]);

  if (!isOrgLoaded || autoLogin === undefined) {
    return null;
  }

  if (shouldRedirectToLogin || testMockAutoLogin) {
    const isHomePath = isRootPage || isFlowsPage;
    return (
      <CustomNavigate
        to={
          "/login" +
          (!isHomePath && !isLoginPage ? `?redirect=${currentPath}` : "")
        }
        replace
      />
    );
  }

  // 🔹 Redirect to /organization
  if (shouldRedirectToOrg) {
    return <CustomNavigate to="/organization" replace />;
  }

  // 🔹 Redirect "/" to "/flows" only if safe
  if (shouldRedirectHome) {
    return <CustomNavigate to="/flows" replace />;
  }

  // ✅ Otherwise render the page
  return children;
};
