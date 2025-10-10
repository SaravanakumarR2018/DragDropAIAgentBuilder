import AlertDisplayArea from "@/alerts/displayArea";
import CrashErrorComponent from "@/components/common/crashErrorComponent";
import { ErrorBoundary } from "react-error-boundary";
import { Outlet , useLocation } from "react-router-dom";
import Landing from "../LandingPage";
import { GenericErrorComponent } from "./components/GenericErrorComponent";
import { useHealthCheck } from "./hooks/use-health-check";

export function AppWrapperPage() {
  const { pathname } = useLocation();
  const { healthCheckTimeout, fetchingHealth, refetch } = useHealthCheck();

  // Render the marketing landing page instead of the authenticated app shell
  // whenever the root route is visited.
  if (pathname === "/") {
    return <Landing />;
  }

  return (
    <div className="flex h-full w-full flex-col">
      <ErrorBoundary
        onReset={() => {
          // any reset function
        }}
        FallbackComponent={CrashErrorComponent}
      >
        <>
          <GenericErrorComponent
            healthCheckTimeout={healthCheckTimeout}
            fetching={fetchingHealth}
            retry={refetch}
          />
          <Outlet />
        </>
      </ErrorBoundary>
      <div className="app-div">
        <AlertDisplayArea />
      </div>
    </div>
  );
}
