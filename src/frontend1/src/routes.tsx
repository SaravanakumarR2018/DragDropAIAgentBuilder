import { Suspense, lazy, useEffect, useRef } from "react";
import {
  Outlet,
  Route,
  createBrowserRouter,
  createRoutesFromElements,
  useLocation,
} from "react-router-dom";

import { ProtectedLoginRoute } from "./components/authorization/authLoginGuard";
import ContextWrapper from "./contexts";
import { CustomNavigate } from "./customization/components/custom-navigate";
import { BASENAME } from "./customization/config-constants";
import { LoadingPage } from "./pages/LoadingPage";
import useAuthStore from "@/stores/authStore";
import { handOffToFullApp } from "@/utils/fullAppRedirect";

const LandingPage = lazy(() => import("./pages/LandingPage"));
const LoginPage = lazy(() =>
  import("./clerk/login-pages").then((module) => ({
    default: module.LoginPage,
  })),
);
const OrganizationPage = lazy(() => import("./clerk/OrganizationPage"));

const MarketingCatchAll = () => {
  const location = useLocation();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isOrgSelected = useAuthStore((state) => state.isOrgSelected);
  const hasRedirected = useRef(false);

  useEffect(() => {
    if (!isAuthenticated) {
      return;
    }

    const sessionOrgSelected =
      typeof window !== "undefined" &&
      sessionStorage.getItem("isOrgSelected") === "true";

    if (hasRedirected.current) {
      return;
    }

    if (isOrgSelected || sessionOrgSelected) {
      hasRedirected.current = true;
      const fullPath = `${location.pathname}${location.search}${location.hash}`;
      handOffToFullApp(fullPath || undefined);
    }
  }, [
    isAuthenticated,
    isOrgSelected,
    location.pathname,
    location.search,
    location.hash,
  ]);

  if (!isAuthenticated) {
    return <CustomNavigate replace to="/" />;
  }

  return <LoadingPage />;
};

const router = createBrowserRouter(
  createRoutesFromElements(
    <Route
      path="/"
      element={
        <ContextWrapper>
          <Outlet />
        </ContextWrapper>
      }
    >
      <Route
        index
        element={
          <Suspense fallback={<LoadingPage />}>
            <LandingPage />
          </Suspense>
        }
      />
      <Route
        path="login"
        element={
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginPage />
            </ProtectedLoginRoute>
          </Suspense>
        }
      />
      <Route
        path="organization"
        element={
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <OrganizationPage />
            </ProtectedLoginRoute>
          </Suspense>
        }
      />
      <Route path="*" element={<MarketingCatchAll />} />
    </Route>,
  ),
  { basename: BASENAME || undefined },
);

export default router;
