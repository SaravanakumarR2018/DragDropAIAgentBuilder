import { Suspense, lazy } from "react";
import {
  createBrowserRouter,
  createRoutesFromElements,
  Outlet,
  Route,
} from "react-router-dom";
import { ProtectedAdminRoute } from "./components/authorization/authAdminGuard";
import { ProtectedRoute } from "./components/authorization/authGuard";
import { ProtectedLoginRoute } from "./components/authorization/authLoginGuard";
import { AuthSettingsGuard } from "./components/authorization/authSettingsGuard";
import ContextWrapper from "./contexts";
import { CustomNavigate } from "./customization/components/custom-navigate";
import { BASENAME } from "./customization/config-constants";
import {
  ENABLE_CUSTOM_PARAM,
  ENABLE_FILE_MANAGEMENT,
} from "./customization/feature-flags";
import { CustomRoutesStore } from "./customization/utils/custom-routes-store";
import { CustomRoutesStorePages } from "./customization/utils/custom-routes-store-pages";
import { IS_CLERK_AUTH } from "./clerk/auth";
import { LoadingPage } from "./pages/LoadingPage";

// Public Shell for lightweight public pages
const PublicShell = () => (
  <Suspense fallback={<LoadingPage />}>
    <Outlet />
  </Suspense>
);

const AppWrapperPage = lazy(() =>
  import("./pages/AppWrapperPage").then((module) => ({
    default: module.AppWrapperPage,
  })),
);
const AppInitPage = lazy(() =>
  import("./pages/AppInitPage").then((module) => ({
    default: module.AppInitPage,
  })),
);
const AppAuthenticatedPage = lazy(() =>
  import("./pages/AppAuthenticatedPage").then((module) => ({
    default: module.AppAuthenticatedPage,
  })),
);
const CustomDashboardWrapperPage = lazy(
  () => import("./customization/components/custom-DashboardWrapperPage"),
);
const CollectionPage = lazy(() => import("./pages/MainPage/pages/main-page"));
const HomePage = lazy(() => import("./pages/MainPage/pages/homePage"));
const FilesPage = lazy(() => import("./pages/MainPage/pages/filesPage"));
const FlowPage = lazy(() => import("./pages/FlowPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const GlobalVariablesPage = lazy(
  () => import("./pages/SettingsPage/pages/GlobalVariablesPage"),
);
const ApiKeysPage = lazy(() => import("./pages/SettingsPage/pages/ApiKeysPage"));
const GeneralPage = lazy(
  () => import("./pages/SettingsPage/pages/GeneralPage"),
);
const ShortcutsPage = lazy(
  () => import("./pages/SettingsPage/pages/ShortcutsPage"),
);
const MessagesPage = lazy(
  () => import("./pages/SettingsPage/pages/messagesPage"),
);
const ViewPage = lazy(() => import("./pages/ViewPage"));
const OrganizationPage = lazy(() => import("./clerk/OrganizationPage"));
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

const AdminPage = lazy(() => import("./pages/AdminPage"));
const DeleteAccountPage = lazy(() => import("./pages/DeleteAccountPage"));
const PlaygroundPage = lazy(() => import("./pages/Playground"));

const router = createBrowserRouter(
  createRoutesFromElements(
    <Route>
      {/* Public Routes */}
      <Route element={<PublicShell />}>
        <Route
          path="/login"
          element={
            <ProtectedLoginRoute>
              <LoginPage />
            </ProtectedLoginRoute>
          }
        />
        <Route
          path="/signup"
          element={
            <ProtectedLoginRoute>
              <SignUp />
            </ProtectedLoginRoute>
          }
        />
        <Route
          path="/login/admin"
          element={
            <ProtectedLoginRoute>
              <LoginAdminPage />
            </ProtectedLoginRoute>
          }
        />
        <Route path="/playground/:id/" element={<PlaygroundPage />} />
      </Route>

      {/* Authenticated Routes */}
      <Route
        path={ENABLE_CUSTOM_PARAM ? "/:customParam?" : "/"}
        element={
          <ContextWrapper>
            <Suspense fallback={<LoadingPage />}>
              <AppWrapperPage />
            </Suspense>
          </ContextWrapper>
        }
      >
        <Route
          path=""
          element={
            <ProtectedRoute>
              <AppInitPage />
            </ProtectedRoute>
          }
        >
          <Route
            path=""
            element={
              <AppAuthenticatedPage />
            }
          >
            <Route
              path=""
              element={
                <CustomDashboardWrapperPage />
              }
            >
              <Route
                path=""
                element={
                  <CollectionPage />
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
                {ENABLE_FILE_MANAGEMENT && (
                  <Route
                    path="files"
                    element={
                      <FilesPage />
                    }
                  />
                )}
                <Route
                  path="flows/"
                  element={
                    <HomePage key="flows" type="flows" />
                  }
                />
                <Route
                  path="components/"
                  element={
                    <HomePage key="components" type="components" />
                  }
                >
                  <Route
                    path="folder/:folderId"
                    element={
                      <HomePage key="components" type="components" />
                    }
                  />
                </Route>
                <Route
                  path="all/"
                  element={
                    <HomePage key="flows" type="flows" />
                  }
                >
                  <Route
                    path="folder/:folderId"
                    element={
                      <HomePage key="flows" type="flows" />
                    }
                  />
                </Route>
                <Route
                  path="mcp/"
                  element={
                    <HomePage key="mcp" type="mcp" />
                  }
                >
                  <Route
                    path="folder/:folderId"
                    element={
                      <HomePage key="mcp" type="mcp" />
                    }
                  />
                </Route>
              </Route>
              <Route
                path="settings"
                element={
                  <SettingsPage />
                }
              >
                <Route index element={<CustomNavigate replace to="general" />} />
                <Route
                  path="global-variables"
                  element={
                    <GlobalVariablesPage />
                  }
                />
                <Route
                  path="api-keys"
                  element={
                    <ApiKeysPage />
                  }
                />
                <Route
                  path="general/:scrollId?"
                  element={
                    <AuthSettingsGuard>
                      <GeneralPage />
                    </AuthSettingsGuard>
                  }
                />
                <Route
                  path="shortcuts"
                  element={
                    <ShortcutsPage />
                  }
                />
                <Route
                  path="messages"
                  element={
                    <MessagesPage />
                  }
                />
                {CustomRoutesStore()}
              </Route>
              {CustomRoutesStorePages()}
              <Route path="account">
                <Route
                  path="delete"
                  element={
                    <DeleteAccountPage />
                  }
                />
              </Route>
              <Route
                path="admin"
                element={
                  <ProtectedAdminRoute>
                    <AdminPage />
                  </ProtectedAdminRoute>
                }
              />
            </Route>
            <Route path="flow/:id/">
              <Route
                path=""
                element={
                  <CustomDashboardWrapperPage />
                }
              >
                <Route
                  path="folder/:folderId/"
                  element={
                    <FlowPage />
                  }
                />
                <Route
                  path=""
                  element={
                    <FlowPage />
                  }
                />
              </Route>
              <Route
                path="view"
                element={
                  <ViewPage />
                }
              />
            </Route>
          </Route>
        </Route>
        <Route
          path="organization"
          element={
            <ProtectedLoginRoute>
              <OrganizationPage />
            </ProtectedLoginRoute>
          }
        />
      </Route>
      <Route path="*" element={<CustomNavigate replace to="/" />} />
    </Route>
  ),
  { basename: BASENAME || undefined },
);

export default router;
