import { Suspense, lazy } from "react";
import {
  Outlet,
  Route,
  createBrowserRouter,
  createRoutesFromElements,
} from "react-router-dom";
import ContextWrapper from "../src/contexts";
import { LoadingPage } from "../src/pages/LoadingPage";
import { ProtectedLoginRoute } from "../src/components/authorization/authLoginGuard";
import { CustomNavigate } from "../src/customization/components/custom-navigate";
import { BASENAME } from "../src/customization/config-constants";
import { ENABLE_CUSTOM_PARAM } from "../src/customization/feature-flags";

const LandingPage = lazy(() => import("../src/pages/LandingPage"));
const LoginPage = lazy(() =>
  import("../src/clerk/login-pages").then((module) => ({
    default: module.LoginPage,
  })),
);
const OrganizationPage = lazy(() => import("../src/clerk/OrganizationPage"));

const router = createBrowserRouter(
  createRoutesFromElements(
    <Route
      path={ENABLE_CUSTOM_PARAM ? "/:customParam?" : "/"}
      element={
        <ContextWrapper key="shell">
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
      <Route path="*" element={<CustomNavigate replace to="flows" />} />
    </Route>,
  ),
  { basename: BASENAME || undefined },
);

export default router;
