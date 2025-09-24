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

// --- Lazy pages ---
const AppWrapperPage = lazy(() =>
  import("./pages/AppWrapperPage").then((m) => ({ default: m.AppWrapperPage }))
);
const AppInitPage = lazy(() =>
  import("./pages/AppInitPage").then((m) => ({ default: m.AppInitPage }))
);
const AppAuthenticatedPage = lazy(() =>
  import("./pages/AppAuthenticatedPage").then((m) => ({ default: m.AppAuthenticatedPage }))
);
const CustomDashboardWrapperPage = lazy(
  () => import("./customization/components/custom-DashboardWrapperPage")
);
const CollectionPage = lazy(() => import("./pages/MainPage/pages/main-page"));
const HomePage = lazy(() => import("./pages/MainPage/pages/homePage"));
const FilesPage = lazy(() => import("./pages/MainPage/pages/filesPage"));
const FlowPage = lazy(() => import("./pages/FlowPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const GlobalVariablesPage = lazy(
  () => import("./pages/SettingsPage/pages/GlobalVariablesPage")
);
const ApiKeysPage = lazy(() => import("./pages/SettingsPage/pages/ApiKeysPage"));
const GeneralPage = lazy(() => import("./pages/SettingsPage/pages/GeneralPage"));
const ShortcutsPage = lazy(
  () => import("./pages/SettingsPage/pages/ShortcutsPage")
);
const MessagesPage = lazy(() => import("./pages/SettingsPage/pages/messagesPage"));
const ViewPage = lazy(() => import("./pages/ViewPage"));
const OrganizationPage = lazy(() => import("./clerk/OrganizationPage"));
const LoginPage = lazy(() =>
  import("./clerk/login-pages").then((m) => ({ default: m.LoginPage }))
);
const SignUp = lazy(() =>
  import("./clerk/login-pages").then((m) => ({ default: m.SignUp }))
);
const LoginAdminPage = lazy(() =>
  import("./clerk/login-pages").then((m) => ({ default: m.LoginAdminPage }))
);
const AdminPage = lazy(() => import("./pages/AdminPage"));
const DeleteAccountPage = lazy(() => import("./pages/DeleteAccountPage"));
const PlaygroundPage = lazy(() => import("./pages/Playground"));

function PublicShell() {
  return (
    <Suspense fallback={<LoadingPage />}>
      <Outlet />
    </Suspense>
  );
}

function AuthenticatedShell() {
  return (
    <ContextWrapper>
      <Suspense fallback={<LoadingPage />}>
        <Outlet />
      </Suspense>
    </ContextWrapper>
  );
}

function PublicIndexRedirect() {
  return (
    <CustomNavigate replace to={IS_CLERK_AUTH ? "/organization" : "/login"} />
  );
}

const router = createBrowserRouter(
  createRoutesFromElements([
    // Standalone route that may need providers (kept isolated)
    <Route path="/playground/:id/" element={<PublicShell />}>
      <Route
        index
        element={
          // Playground still needs ContextWrapper -> mount locally to avoid polluting public shell
          <ContextWrapper>
            <Suspense fallback={<LoadingPage />}>
              <PlaygroundPage />
            </Suspense>
          </ContextWrapper>
        }
      />
    </Route>,

    // ===== PUBLIC ROUTER (minimal providers) =====
    <Route path={ENABLE_CUSTOM_PARAM ? "/:customParam?" : "/"} element={<PublicShell />}>
      {/* Public landing shunt */}
      <Route index element={<PublicIndexRedirect />} />

      {/* Public auth/marketing pages: no ContextWrapper */}
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
            <SignUp />
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
        path="login/admin"
        element={
          <ProtectedLoginRoute>
            <LoginAdminPage />
          </ProtectedLoginRoute>
        }
      />
    </Route>,

    // ===== AUTHENTICATED ROUTER (heavy providers) =====
    <Route path={ENABLE_CUSTOM_PARAM ? "/:customParam?" : "/"} element={<AuthenticatedShell />}>
      <Route
        path=""
        element={
          <AppWrapperPage />
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
          <Route path="" element={<AppAuthenticatedPage />}>
            <Route path="" element={<CustomDashboardWrapperPage />}>
              <Route path="" element={<CollectionPage />}>
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
                  <Route path="files" element={<FilesPage />} />
                )}
                <Route path="flows/" element={<HomePage key="flows" type="flows" />} />
                <Route path="components/" element={<HomePage key="components" type="components" />}>
                  <Route path="folder/:folderId" element={<HomePage key="components" type="components" />} />
                </Route>
                <Route path="all/" element={<HomePage key="flows" type="flows" />}>
                  <Route path="folder/:folderId" element={<HomePage key="flows" type="flows" />} />
                </Route>
                <Route path="mcp/" element={<HomePage key="mcp" type="mcp" />}>
                  <Route path="folder/:folderId" element={<HomePage key="mcp" type="mcp" />} />
                </Route>
              </Route>

              {/* Settings */}
              <Route path="settings" element={<SettingsPage />}>
                <Route index element={<CustomNavigate replace to="general" />} />
                <Route path="global-variables" element={<GlobalVariablesPage />} />
                <Route path="api-keys" element={<ApiKeysPage />} />
                <Route path="general/:scrollId?" element={<AuthSettingsGuard><GeneralPage /></AuthSettingsGuard>} />
                <Route path="shortcuts" element={<ShortcutsPage />} />
                <Route path="messages" element={<MessagesPage />} />
                {CustomRoutesStore()}
              </Route>
              {CustomRoutesStorePages()}

              {/* Account */}
              <Route path="account">
                <Route path="delete" element={<DeleteAccountPage />} />
              </Route>

              {/* Admin */}
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
              <Route path="" element={<CustomDashboardWrapperPage />}>
                <Route path="folder/:folderId/" element={<FlowPage />} />
                <Route path="" element={<FlowPage />} />
              </Route>
              <Route path="view" element={<ViewPage />} />
            </Route>
          </Route>
        </Route>
      </Route>
    </Route>,

    // Catch-all
    <Route path="*" element={<CustomNavigate replace to="/" />} />,
  ]),
  { basename: BASENAME || undefined }
);

export default router;
