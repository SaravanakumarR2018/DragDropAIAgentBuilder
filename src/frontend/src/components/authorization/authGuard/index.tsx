import { useAuth as useClerkAuth, useOrganization } from "@clerk/clerk-react";
import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import {
  IS_AUTO_LOGIN,
  LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS,
  LANGFLOW_ACCESS_TOKEN_EXPIRE_SECONDS_ENV,
} from "@/constants/constants";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import { useRefreshAccessToken } from "@/controllers/API/queries/auth";
import { CustomNavigate } from "@/customization/components/custom-navigate";
import useAuthStore from "@/stores/authStore";

export const ProtectedRoute = ({ children }) => {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const autoLogin = useAuthStore((state) => state.autoLogin);
  const isOrgSelectedStore = useAuthStore((state) => state.isOrgSelected);

  const { mutate: mutateRefresh } = useRefreshAccessToken();
  const testMockAutoLogin = sessionStorage.getItem("testMockAutoLogin");

  // Clerk values
  const { organization, isLoaded: isOrgLoaded } = useOrganization();
  const isOrgSelected =
    Boolean(organization?.id) ||
    isOrgSelectedStore ||
    sessionStorage.getItem("isOrgSelected") === "true";
  const { isLoaded: isClerkLoaded, isSignedIn, getToken } = useClerkAuth();

  // Get current path
  const location = useLocation();
  const currentPath = location.pathname;
  const currentSearch = location.search;
  const isLoginPage = currentPath.includes("login");
  const isOrgPage = currentPath.includes("organization");
  const isAdminPage = currentPath.includes("/admin");
  const isRootPage = currentPath === "/";
  const isFlowsPage = currentPath.includes("/flows");
  const isPricingPage = currentPath.includes("/pricing");
  const hasPricingBypassParam =
    new URLSearchParams(currentSearch).get("pricing_bypass") === "1";
  const hasPricingBypassSession =
    sessionStorage.getItem("pricingBypass") === "1";
  const isPricingBypass =
    isFlowsPage &&
    (hasPricingBypassParam || hasPricingBypassSession) &&
    isSignedIn === true &&
    isOrgSelected;

  // 🔹 Billing state
  const [hasAccess, setHasAccess] = useState<boolean | null>(null);
  const [isCheckingAccess, setIsCheckingAccess] = useState(false);

  useEffect(() => {
    if (!isFlowsPage || !isPricingBypass) return;

    // One-time temporary bypass token from Pricing page
    sessionStorage.removeItem("pricingBypass");
  }, [isFlowsPage, isPricingBypass]);

  // 🔹 Billing check for /flows
  useEffect(() => {
    if (!isFlowsPage || isPricingBypass) return;
    if (!isOrgLoaded || !isClerkLoaded || !isSignedIn || !isOrgSelected) return;

    let active = true;
    setIsCheckingAccess(true);

    (async () => {
      try {
        const token = await getToken();
        if (!token) {
          if (active) setHasAccess(false);
          return;
        }
        const response = await api.get(getURL("BILLING_ACCESS"), {
          headers: { Authorization: `Bearer ${token}` },
        });
        console.log("[ProtectedRoute] Billing access response:", response.data);
        if (active) {
          setHasAccess(response.data?.has_access === true);
        }
      } catch {
        if (active) setHasAccess(false);
      } finally {
        if (active) setIsCheckingAccess(false);
      }
    })();

    return () => {
      active = false;
    };
  }, [
    isFlowsPage,
    isPricingBypass,
    isOrgLoaded,
    isClerkLoaded,
    isSignedIn,
    isOrgSelected,
    getToken,
  ]);

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

  // ✅ Root path "/" is PUBLIC - don't redirect unauthenticated users
  if (isRootPage) {
    return children;
  }

  // ❌ Pricing should NOT be public
  if (isPricingPage) {
    if (!isOrgLoaded || !isClerkLoaded || autoLogin === undefined) {
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

  // 🔒 Protect /flows with billing check
  if (isFlowsPage) {
    if (!isOrgLoaded || !isClerkLoaded || isSignedIn === undefined) {
      return null;
    }

    if (isSignedIn && !isOrgSelected) {
      return <CustomNavigate to="/organization" replace />;
    }

    if (isPricingBypass) {
      // Temporary bypass from pricing placeholder until checkout is implemented
    } else if (isSignedIn && hasAccess === null) {
      return null;
    }

    if (isCheckingAccess) {
      return null;
    }

    if (!isPricingBypass && hasAccess === false) {
      return <CustomNavigate to="/pricing" replace />;
    }
  }

  // 1️⃣ Redirect to login if not authenticated (for protected pages only)
  const shouldRedirectToLogin =
    isOrgLoaded &&
    (!isSignedIn || (!isAuthenticated && !isFlowsPage)) &&
    autoLogin !== undefined &&
    (!autoLogin || !IS_AUTO_LOGIN);

  // 2️⃣ Redirect to organization selection if signed in but no org yet
  const shouldRedirectToOrg =
    isOrgLoaded &&
    isSignedIn &&
    !isOrgSelected &&
    !isOrgPage &&
    !isAdminPage &&
    !isLoginPage;

  // ✅ 3️⃣ DO NOT redirect "/" to "/flows" - authenticated users should stay on landing page
  const shouldRedirectHome = false;

  if (!isOrgLoaded || !isClerkLoaded || autoLogin === undefined) {
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
