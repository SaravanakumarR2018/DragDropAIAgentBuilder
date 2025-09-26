import { Suspense, lazy } from "react";
import {
  Outlet,
  Route,
  createBrowserRouter,
  createRoutesFromElements,
} from "react-router-dom";

import { ProtectedRoute } from "@/components/authorization/authGuard";
import { ProtectedLoginRoute } from "@/components/authorization/authLoginGuard";
import { BASENAME } from "@/customization/config-constants";
import { LandingContextWrapper } from "./landing-context-wrapper";
import { LoadingPage } from "@/pages/LoadingPage";

const LandingPage = lazy(() =>
  import("@/pages/LandingPage").then((module) => ({
    default: module.default,
  })),
);
const LoginPage = lazy(() =>
  import("@/clerk/login-pages").then((module) => ({
    default: module.LoginPage,
  })),
);
const SignUpPage = lazy(() =>
  import("@/clerk/login-pages").then((module) => ({
    default: module.SignUp,
  })),
);
const OrganizationPage = lazy(() => import("@/clerk/OrganizationPage"));
const LogoutPage = lazy(() => import("./pages/LogoutPage"));

const LandingLayout = () => (
  <LandingContextWrapper>
    <Suspense fallback={<LoadingPage />}>
      <Outlet />
    </Suspense>
  </LandingContextWrapper>
);

export const landingRouter = createBrowserRouter(
  createRoutesFromElements(
    <Route path="/" element={<LandingLayout />}>
      <Route index element={<LandingPage />} />
      <Route
        path="login"
        element={
          <ProtectedLoginRoute>
            <LoginPage />
          </ProtectedLoginRoute>
        }
      />
      <Route path="sign-up" element={<SignUpPage />} />
      <Route
        path="organization"
        element={
          <ProtectedRoute>
            <OrganizationPage />
          </ProtectedRoute>
        }
      />
      <Route path="logout" element={<LogoutPage />} />
    </Route>,
  ),
  { basename: BASENAME || "" },
);
