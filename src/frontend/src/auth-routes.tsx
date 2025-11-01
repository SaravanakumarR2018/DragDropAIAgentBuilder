import { Suspense, lazy } from "react";
import {
  createBrowserRouter,
  createRoutesFromElements,
  Outlet,
  Route,
} from "react-router-dom";
import { ProtectedLoginRoute } from "./components/authorization/authLoginGuard";
import { AuthShellWrapper } from "./contexts/authShellWrapper";
import { CustomNavigate } from "./customization/components/custom-navigate";
import { BASENAME } from "./customization/config-constants";
import { ENABLE_CUSTOM_PARAM } from "./customization/feature-flags";
import { LoadingPage } from "./pages/LoadingPage";

const LoginPage = lazy(() =>
  import("./clerk/login-pages").then((module) => ({
    default: module.LoginPage,
  })),
);
const SignUp = lazy(() =>
  import("./clerk/login-pages").then((module) => ({
    default: module.SignUp,
  })),
);
const LoginAdminPage = lazy(() =>
  import("./clerk/login-pages").then((module) => ({
    default: module.LoginAdminPage,
  })),
);
const OrganizationPage = lazy(() => import("./clerk/OrganizationPage"));

const authRouter = createBrowserRouter(
  createRoutesFromElements(
    <Route
      path={ENABLE_CUSTOM_PARAM ? "/:customParam?" : "/"}
      element={
        <AuthShellWrapper>
          <Outlet />
        </AuthShellWrapper>
      }
    >
      <Route
        index
        element={
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginPage />
            </ProtectedLoginRoute>
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
        path="signup"
        element={
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <SignUp />
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
      <Route
        path="login/admin"
        element={
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginAdminPage />
            </ProtectedLoginRoute>
          </Suspense>
        }
      />
      <Route path="*" element={<CustomNavigate replace to="/login" />} />
    </Route>,
  ),
  { basename: BASENAME || undefined },
);

export default authRouter;
