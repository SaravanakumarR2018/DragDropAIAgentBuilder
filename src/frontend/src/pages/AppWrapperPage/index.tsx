import { Suspense, lazy } from "react";
import { LoadingPage } from "../LoadingPage";
import { useLocation } from "react-router-dom";
import Landing from "../LandingPage";
import AlertDisplayArea from "@/alerts/displayArea";
import CrashErrorComponent from "@/components/common/crashErrorComponent";
import { ErrorBoundary } from "react-error-boundary";
import useAuthStore from "@/stores/authStore";
import { Outlet , useLocation } from "react-router-dom";
import Landing from "../LandingPage";
import { GenericErrorComponent } from "./components/GenericErrorComponent";
import { useHealthCheck } from "./hooks/use-health-check";

const AuthenticatedAppWrapper = lazy(() =>
  import("./components/AuthenticatedAppWrapper").then((module) => ({
    default: module.AuthenticatedAppWrapper,
  })),
);
export function AppWrapperPage() {
  const { pathname } = useLocation();

  // Render the marketing landing page when visitor hits the root route
  // regardless of authentication status
  if (pathname === "/") {
    return <Landing />;
  }
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const { pathname } = useLocation();
  const { healthCheckTimeout, fetchingHealth, refetch } = useHealthCheck();

  // Render the marketing landing page when visitor hits the root route
  // regardless of authentication status
  if (pathname === "/") {
    return <Landing />;
  }

  return (
    <Suspense fallback={<LoadingPage />}>
      <AuthenticatedAppWrapper />
    </Suspense>
  );
}
