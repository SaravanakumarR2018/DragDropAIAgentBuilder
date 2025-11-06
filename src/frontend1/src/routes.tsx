import { Suspense, lazy } from "react";
import {
  createBrowserRouter,
  createRoutesFromElements,
  Route,
} from "react-router-dom";
import { ProtectedLoginRoute } from "./components/authorization/authLoginGuard";
import ContextWrapper from "./contexts";
import { LoadingPage } from "./pages/LoadingPage";
import { CatchAllRedirect } from "./routes/CatchAllRedirect";
import { BASENAME } from "./customization/config-constants";

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

const router = createBrowserRouter(
  createRoutesFromElements([
    <Route
      path="/"
      element={
        <ContextWrapper>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginPage />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path="/login"
      element={
        <ContextWrapper>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginPage />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path="/organization"
      element={
        <ContextWrapper>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <OrganizationPage />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path="/signup"
      element={
        <ContextWrapper>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <SignUp />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path="/login/admin"
      element={
        <ContextWrapper>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginAdminPage />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route path="*" element={<CatchAllRedirect />} />,
  ]),
  { basename: BASENAME || undefined },
);

export default router;
