import { Suspense, lazy } from "react";
import {
  createBrowserRouter,
  createRoutesFromElements,
  Outlet,
  Route,
} from "react-router-dom";

import { ProtectedRoute } from "./components/authorization/authGuard";
import { ProtectedLoginRoute } from "./components/authorization/authLoginGuard";
import { ProtectedAdminRoute } from "./components/authorization/authAdminGuard";
import { AuthSettingsGuard } from "./components/authorization/authSettingsGuard";
import { LoadingPage } from "./pages/LoadingPage";
import { BASENAME } from "./customization/config-constants";
import { CustomNavigate } from "./customization/components/custom-navigate";
import ContextWrapper from "./contexts";
import { IS_CLERK_AUTH } from "./clerk/auth";

// ✅ Lightweight shell for public routes (no ContextWrapper, no heavy deps)
function PublicShell() {
  return (
    <Suspense fallback={<LoadingPage />}>
      <Outlet />
    </Suspense>
  );
}

// ✅ Heavy shell for authenticated app
function AppShell() {
  return (
    <ContextWrapper>
      <Outlet />
    </ContextWrapper>
  );
}

// Lazy imports for public pages
const LoginPage = lazy(() =>
  import("./clerk/login-pages").then((m) => ({ default: m.LoginPage })),
);
const SignUpPage = lazy(() =>
  import("./clerk/login-pages").then((m) => ({ default: m.SignUp })),
);
const OrganizationPage = lazy(() => import("./clerk/OrganizationPage"));
const LandingPage = lazy(() => import("./pages/LandingPage")); // if you have one

// Lazy imports for heavy app
const AppWrapperPage = lazy(() =>
  import("./pages/AppWrapperPage").then((m) => ({ default: m.AppWrapperPage })),
);
const AppInitPage = lazy(() =>
  import("./pages/AppInitPage").then((m) => ({ default: m.AppInitPage })),
);
const AppAuthenticatedPage = lazy(() =>
  import("./pages/AppAuthenticatedPage").then((m) => ({ default: m.AppAuthenticatedPage })),
);
const CustomDashboardWrapperPage = lazy(
  () => import("./customization/components/custom-DashboardWrapperPage"),
);
const HomePage = lazy(() => import("./pages/MainPage/pages/homePage"));
const FilesPage = lazy(() => import("./pages/MainPage/pages/filesPage"));
const FlowPage = lazy(() => import("./pages/FlowPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const ViewPage = lazy(() => import("./pages/ViewPage"));
const AdminPage = lazy(() => import("./pages/AdminPage"));

const router = createBrowserRouter(
  createRoutesFromElements([
    // --- Public Routes ---
    <Route element={<PublicShell />}>
      <Route index element={<LandingPage />} />
      <Route
        path="login"
        element={
          <ProtectedLoginRoute>
            <LoginPage />
          </ProtectedLoginRoute>
        }
      />
      <Route
        path="signup"
        element={
          <ProtectedLoginRoute>
            <SignUpPage />
          </ProtectedLoginRoute>
        }
      />
      <Route
        path="organization"
        element={
          <ProtectedLoginRoute>
            <OrganizationPage />
          </ProtectedLoginRoute>
        }
      />
    </Route>,

    // --- Authenticated App ---
    <Route element={<AppShell />}>
      <Route
        path=""
        element={
          <Suspense fallback={<LoadingPage />}>
            <AppWrapperPage />
          </Suspense>
        }
      >
        <Route
          path=""
          element={
            <Suspense fallback={<LoadingPage />}>
              <ProtectedRoute>
                <AppInitPage />
              </ProtectedRoute>
            </Suspense>
          }
        >
          <Route
            path=""
            element={
              <Suspense fallback={<LoadingPage />}>
                <AppAuthenticatedPage />
              </Suspense>
            }
          >
            {/* main dashboard tree */}
            <Route
              path=""
              element={
                <Suspense fallback={<LoadingPage />}>
                  <CustomDashboardWrapperPage />
                </Suspense>
              }
            >
              <Route
                index
                element={
                  IS_CLERK_AUTH ? (
                    <CustomNavigate replace to="/organization" />
                  ) : (
                    <CustomNavigate replace to="flows" />
                  )
                }
              />
              <Route
                path="flows"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <HomePage key="flows" type="flows" />
                  </Suspense>
                }
              />
              <Route
                path="files"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <FilesPage />
                  </Suspense>
                }
              />
            </Route>

            {/* settings */}
            <Route
              path="settings"
              element={
                <Suspense fallback={<LoadingPage />}>
                  <SettingsPage />
                </Suspense>
              }
            />
            <Route
              path="flow/:id/"
              element={
                <Suspense fallback={<LoadingPage />}>
                  <FlowPage />
                </Suspense>
              }
            />
            <Route
              path="view"
              element={
                <Suspense fallback={<LoadingPage />}>
                  <ViewPage />
                </Suspense>
              }
            />
            <Route
              path="admin"
              element={
                <Suspense fallback={<LoadingPage />}>
                  <ProtectedAdminRoute>
                    <AdminPage />
                  </ProtectedAdminRoute>
                </Suspense>
              }
            />
          </Route>
        </Route>
      </Route>
    </Route>,
  ]),
  { basename: BASENAME || undefined },
);

export default router;
