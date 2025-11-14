import { Suspense, lazy } from "react";
import {
  Outlet,
  Route,
  RouterProvider,
  createBrowserRouter,
  createRoutesFromElements,
} from "react-router-dom";
import ContextWrapper from "@/contexts";
import { ProtectedLoginRoute } from "@/components/authorization/authLoginGuard";
import { LoadingPage } from "@/pages/LoadingPage";
import { BASENAME } from "@/customization/config-constants";
import { LoginPage, LoginAdminPage, SignUp } from "@/clerk/login-pages";
import OrganizationPage from "@/clerk/OrganizationPage";
import FullPageReload from "./full-page-reload";

const LandingPage = lazy(() => import("@/pages/LandingPage"));

const router = createBrowserRouter(
  createRoutesFromElements(
    <Route
      path="/"
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
        path="login/admin"
        element={
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginAdminPage />
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
      <Route path="flows/*" element={<FullPageReload />} />
      <Route path="flow/*" element={<FullPageReload />} />
      <Route path="*" element={<FullPageReload />} />
    </Route>,
  ),
  { basename: BASENAME || undefined },
);

export default function ShellRouter() {
  return <RouterProvider router={router} />;
}
