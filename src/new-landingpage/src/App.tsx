import { useAuth } from "@clerk/clerk-react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import type { PropsWithChildren } from "react";
import { LANDING_BASENAME } from "./landingRoutes";
import NewLandingPageLogin from "./NewLandingPageLogin";
import OrganizationOnboarding from "./OrganizationOnboarding";
import "./App.css";
import { useCookies } from "react-cookie";
import LandingPage from "./LandingPage";
import {
  hasWorkspaceSession,
  LANGFLOW_ACCESS_TOKEN,
  LANGFLOW_REFRESH_TOKEN,
} from "./session";

function SessionRedirect({ children }: PropsWithChildren) {
  const [cookies] = useCookies([LANGFLOW_ACCESS_TOKEN, LANGFLOW_REFRESH_TOKEN]);
  const workspaceReady = hasWorkspaceSession(cookies);

  if (workspaceReady) {
    console.log("[App] SessionRedirect detected workspace; sending to /flows");
    window.location.assign("/flows");
    return null;
  }

  return <>{children}</>;
}

function FlowsRedirect() {
  console.log("[App] Redirecting to /flows");
  window.location.assign("/flows");
  return null;
}

function RootRoute() {
  const { isSignedIn } = useAuth();
  const [cookies] = useCookies([LANGFLOW_ACCESS_TOKEN, LANGFLOW_REFRESH_TOKEN]);

  console.log("[App] RootRoute render", { isSignedIn });

  if (isSignedIn) {
    const workspaceReady = hasWorkspaceSession(cookies);
    const destination = workspaceReady ? "/flows" : "/organization";

    console.log("[App] Redirecting signed-in user from root", {
      workspaceReady,
      destination,
    });

    if (workspaceReady) {
      return <FlowsRedirect />;
    }
    return <Navigate to={destination} replace />;
  }

  return <LandingPage />;
}

export default function App() {
  console.log(`[App] App mounted with basename ${LANDING_BASENAME}`);

  return (
    <BrowserRouter basename={LANDING_BASENAME}>
      <Routes>
        <Route path="/" element={<RootRoute />} />
        <Route
          path="/login"
          element={
            <SessionRedirect>
              <NewLandingPageLogin />
            </SessionRedirect>
          }
        />
        <Route
          path="/organization"
          element={
            <SessionRedirect>
              <OrganizationOnboarding />
            </SessionRedirect>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
