import { Suspense, lazy } from "react";
import {
  Navigate,
  Outlet,
  Route,
  createBrowserRouter,
  createRoutesFromElements,
} from "react-router-dom";
import { ProtectedRoute } from "./components/authorization/authGuard";
import { ProtectedLoginRoute } from "./components/authorization/authLoginGuard";
import ContextWrapper from "./contexts";
import { BASENAME } from "./customization/config-constants";
import { LoadingPage } from "./pages/LoadingPage";

const LandingPage = lazy(() => import("./pages/LandingPage"));
const LoginPage = lazy(() =>
  import("./clerk/login-pages").then((module) => ({
    default: module.LoginPage,
  })),
);
const OrganizationPage = lazy(() => import("./clerk/OrganizationPage"));

const router = createBrowserRouter(
  createRoutesFromElements(
    <Route
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
            <ProtectedRoute>
              <OrganizationPage />
            </ProtectedRoute>
          </Suspense>
        }
      />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Route>,
  ),
  { basename: BASENAME || undefined },
);

export default router;
