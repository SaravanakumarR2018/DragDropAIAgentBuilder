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
import ContextWrapper from "./contexts";
import CustomDashboardWrapperPage from "./customization/components/custom-DashboardWrapperPage";
import { CustomNavigate } from "./customization/components/custom-navigate";
import { BASENAME } from "./customization/config-constants";
import {
  ENABLE_CUSTOM_PARAM,
  ENABLE_FILE_MANAGEMENT,
  ENABLE_KNOWLEDGE_BASES,
} from "./customization/feature-flags";
import { CustomRoutesStore } from "./customization/utils/custom-routes-store";
import { CustomRoutesStorePages } from "./customization/utils/custom-routes-store-pages";
import { AppAuthenticatedPage } from "./pages/AppAuthenticatedPage";
import { LoadingPage } from "./pages/LoadingPage";
import { AppInitPage } from "./pages/AppInitPage";
import { AppWrapperPage } from "./pages/AppWrapperPage";
import FlowPage from "./pages/FlowPage";
import FilesPage from "./pages/MainPage/pages/filesPage";
import HomePage from "./pages/MainPage/pages/homePage";
import KnowledgePage from "./pages/MainPage/pages/knowledgePage";
import SourceChunksPage from "./pages/MainPage/pages/knowledgePage/sourceChunksPage/SourceChunksPage";
import CollectionPage from "./pages/MainPage/pages/main-page";
import SettingsPage from "./pages/SettingsPage";
import ApiKeysPage from "./pages/SettingsPage/pages/ApiKeysPage";
import GlobalVariablesPage from "./pages/SettingsPage/pages/GlobalVariablesPage";
import MCPServersPage from "./pages/SettingsPage/pages/MCPServersPage";
import ModelProvidersPage from "./pages/SettingsPage/pages/ModelProvidersPage";
import MessagesPage from "./pages/SettingsPage/pages/messagesPage";
import ShortcutsPage from "./pages/SettingsPage/pages/ShortcutsPage";
import ViewPage from "./pages/ViewPage";
import { CatchAllRedirect } from "./routes/CatchAllRedirect";

const OrganizationPage = lazy(() => import("./clerk/OrganizationPage"));
const DebuggingPage = lazy(
  () => import("./pages/SettingsPage/pages/DebuggingPage"),
);
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
const TermsOfServicePage = lazy(() => import("./pages/TermsOfServicePage"));
const PrivacyPolicyPage = lazy(() => import("./pages/PrivacyPolicyPage"));
const RefundPolicyPage = lazy(() => import("./pages/RefundPolicyPage"));

const router = createBrowserRouter(
  createRoutesFromElements([
    <Route path="/playground/:id/">
      <Route
        path=""
        element={
          <ContextWrapper key={1}>
            <PlaygroundPage />
          </ContextWrapper>
        }
      />
    </Route>,
    <Route
      path={ENABLE_CUSTOM_PARAM ? "/:customParam?" : "/"}
      element={
        <ContextWrapper key={2}>
          <Outlet />
        </ContextWrapper>
      }
    >
      <Route path="" element={<AppInitPage />}>
        <Route path="" element={<AppWrapperPage />}>
          <Route
            path=""
            element={
              <ProtectedRoute>
                <Outlet />
              </ProtectedRoute>
            }
          >
            <Route path="" element={<AppAuthenticatedPage />}>
              <Route path="" element={<CustomDashboardWrapperPage />}>
                <Route path="" element={<CollectionPage />}>
                  <Route
                    index
                    element={<CustomNavigate replace to={"flows"} />}
                  />
                  {ENABLE_FILE_MANAGEMENT && (
                    <Route path="assets">
                      <Route
                        index
                        element={<CustomNavigate replace to="files" />}
                      />
                      <Route path="files" element={<FilesPage />} />
                      {ENABLE_KNOWLEDGE_BASES && (
                        <>
                          <Route
                            path="knowledge-bases"
                            element={<KnowledgePage />}
                          />
                          <Route
                            path="knowledge-bases/:sourceId/chunks"
                            element={<SourceChunksPage />}
                          />
                        </>
                      )}
                    </Route>
                  )}
                  <Route
                    path="flows/"
                    element={<HomePage key="flows" type="flows" />}
                  />

                  <Route
                    path="components/"
                    element={<HomePage key="components" type="components" />}
                  >
                    <Route
                      path="folder/:folderId"
                      element={<HomePage key="components" type="components" />}
                    />
                  </Route>
                  <Route
                    path="all/"
                    element={<HomePage key="flows" type="flows" />}
                  >
                    <Route
                      path="folder/:folderId"
                      element={<HomePage key="flows" type="flows" />}
                    />
                  </Route>
                  <Route
                    path="mcp/"
                    element={<HomePage key="mcp" type="mcp" />}
                  >
                    <Route
                      path="folder/:folderId"
                      element={<HomePage key="mcp" type="mcp" />}
                    />
                  </Route>
                </Route>
                {/* ✅ FIX: flow route moved inside CollectionPage */}
                  <Route path="flow/:id">
                      <Route index element={<FlowPage />} />
                      <Route path="folder/:folderId" element={<FlowPage />} />
                      <Route path="view" element={<ViewPage />} />
                  </Route>

                {/* SETTINGS */}
                <Route path="settings" element={<SettingsPage />}>
                  <Route
                    index
                    element={<CustomNavigate replace to={"mcp-servers"} />}
                  />
                  <Route
                    path="global-variables"
                    element={<GlobalVariablesPage />}
                  />
                  <Route
                    path="model-providers"
                    element={<ModelProvidersPage />}
                  />
                  <Route path="mcp-servers" element={<MCPServersPage />} />

                  <Route path="api-keys" element={<ApiKeysPage />} />
                  <Route path="shortcuts" element={<ShortcutsPage />} />
                  <Route path="messages" element={<MessagesPage />} />
                  <Route path="debugging" element={<DebuggingPage/>}/>
                  {CustomRoutesStore()}
                </Route>
                {CustomRoutesStorePages()}
                <Route path="account">
                  <Route path="delete" element={<DeleteAccountPage />} />
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
            </Route>
          </Route>
          {/* Public policy routes */}
          <Route
          path="terms-of-service"
          element={
            <Suspense fallback={<LoadingPage />}>
              <TermsOfServicePage />
            </Suspense>
          }
        />
        <Route
          path="privacy-policy"
          element={
            <Suspense fallback={<LoadingPage />}>
              <PrivacyPolicyPage />
            </Suspense>
          }
        />
        <Route
          path="refund-policy"
          element={
            <Suspense fallback={<LoadingPage />}>
              <RefundPolicyPage />
            </Suspense>
          }
        />
          <Route
            path="login"
            element={
              <ProtectedLoginRoute>
                <LoginPage />
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

          <Route
            path="signup"
            element={
              <ProtectedLoginRoute>
                <SignUp />
              </ProtectedLoginRoute>
            }
          />
          <Route
            path="login/admin"
            element={
              <ProtectedLoginRoute>
                <LoginAdminPage />
              </ProtectedLoginRoute>
            }
          />
        </Route>
      </Route>
      <Route path="*" element={<CatchAllRedirect />} />
    </Route>,
  ]),
  { basename: BASENAME || undefined }
);

export default router;