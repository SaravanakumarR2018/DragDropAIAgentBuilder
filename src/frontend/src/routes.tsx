import { Suspense, lazy } from "react";
import { createBrowserRouter, createRoutesFromElements, Route } from "react-router-dom";
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
import { LoadingPage } from "./pages/LoadingPage";
import { CollectionIndexRedirect } from "./routes/CollectionIndexRedirect";
import { CatchAllRedirect } from "./routes/CatchAllRedirect";
import { WorkspaceLoadingPage } from "./pages/WorkspaceLoadingPage";

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

const withCustomPrefix = (path: string) =>
  ENABLE_CUSTOM_PARAM ? `/:customParam${path}` : path;

const router = createBrowserRouter(
  createRoutesFromElements([
    <Route
      path={withCustomPrefix("/playground/:id/")}
      element={
        <ContextWrapper key={1}>
          <Suspense fallback={<LoadingPage />}>
            <PlaygroundPage />
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path={withCustomPrefix("/app")}
      element={
        <ContextWrapper key={2}>
          <Suspense fallback={<LoadingPage />}>
            <AppWrapperPage />
          </Suspense>
        </ContextWrapper>
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
          <Route
            path=""
            element={
              <Suspense fallback={<LoadingPage />}>
                <CustomDashboardWrapperPage />
              </Suspense>
            }
          >
            <Route
              path=""
              element={
                <Suspense fallback={<LoadingPage />}>
                  <CollectionPage />
                </Suspense>
              }
            >
              <Route index element={<CollectionIndexRedirect />} />
              {ENABLE_FILE_MANAGEMENT && (
                <Route
                  path="files"
                  element={
                    <Suspense fallback={<LoadingPage />}>
                      <FilesPage />
                    </Suspense>
                  }
                />
              )}
              <Route
                path="flows/"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <HomePage key="flows" type="flows" />
                  </Suspense>
                }
              />
              <Route
                path="components/"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <HomePage key="components" type="components" />
                  </Suspense>
                }
              >
                <Route
                  path="folder/:folderId"
                  element={
                    <Suspense fallback={<LoadingPage />}>
                      <HomePage key="components" type="components" />
                    </Suspense>
                  }
                />
              </Route>
              <Route
                path="all/"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <HomePage key="flows" type="flows" />
                  </Suspense>
                }
              >
                <Route
                  path="folder/:folderId"
                  element={
                    <Suspense fallback={<LoadingPage />}>
                      <HomePage key="flows" type="flows" />
                    </Suspense>
                  }
                />
              </Route>
              <Route
                path="mcp/"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <HomePage key="mcp" type="mcp" />
                  </Suspense>
                }
              >
                <Route
                  path="folder/:folderId"
                  element={
                    <Suspense fallback={<LoadingPage />}>
                      <HomePage key="mcp" type="mcp" />
                    </Suspense>
                  }
                />
              </Route>
            </Route>
            <Route
              path="settings"
              element={
                <Suspense fallback={<LoadingPage />}>
                  <SettingsPage />
                </Suspense>
              }
            >
              <Route index element={<CustomNavigate replace to="general" />} />
              <Route
                path="global-variables"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <GlobalVariablesPage />
                  </Suspense>
                }
              />
              <Route
                path="api-keys"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <ApiKeysPage />
                  </Suspense>
                }
              />
              <Route
                path="general/:scrollId?"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <AuthSettingsGuard>
                      <GeneralPage />
                    </AuthSettingsGuard>
                  </Suspense>
                }
              />
              <Route
                path="shortcuts"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <ShortcutsPage />
                  </Suspense>
                }
              />
              <Route
                path="messages"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <MessagesPage />
                  </Suspense>
                }
              />
              {CustomRoutesStore()}
            </Route>
            {CustomRoutesStorePages()}
            <Route path="account">
              <Route
                path="delete"
                element={
                  <Suspense fallback={<LoadingPage />}>
                    <DeleteAccountPage />
                  </Suspense>
                }
              />
            </Route>
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
          <Route path="flow/:id/">
            <Route
              path=""
              element={
                <Suspense fallback={<LoadingPage />}>
                  <CustomDashboardWrapperPage />
                </Suspense>
              }
            >
              <Route
                path="folder/:folderId/"
                element={
                  <Suspense fallback={<WorkspaceLoadingPage />}>
                    <FlowPage />
                  </Suspense>
                }
              />
              <Route
                path=""
                element={
                  <Suspense fallback={<WorkspaceLoadingPage />}>
                    <FlowPage />
                  </Suspense>
                }
              />
            </Route>
            <Route
              path="view"
              element={
                <Suspense fallback={<LoadingPage />}>
                  <ViewPage />
                </Suspense>
              }
            />
          </Route>
        </Route>
      </Route>
    </Route>,
    <Route
      path={withCustomPrefix("/login")}
      element={
        <ContextWrapper key={3}>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginPage />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path={withCustomPrefix("/organization")}
      element={
        <ContextWrapper key={4}>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <OrganizationPage />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path={withCustomPrefix("/signup")}
      element={
        <ContextWrapper key={5}>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <SignUp />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    <Route
      path={withCustomPrefix("/login/admin")}
      element={
        <ContextWrapper key={6}>
          <Suspense fallback={<LoadingPage />}>
            <ProtectedLoginRoute>
              <LoginAdminPage />
            </ProtectedLoginRoute>
          </Suspense>
        </ContextWrapper>
      }
    />,
    ...(ENABLE_CUSTOM_PARAM
      ? [
          <Route
            key="custom-catchall"
            path={withCustomPrefix("/*")}
            element={<CatchAllRedirect />}
          />,
        ]
      : []),
    <Route path="*" element={<CatchAllRedirect />} />,
  ]),
  { basename: BASENAME || undefined },
);

export default router;
