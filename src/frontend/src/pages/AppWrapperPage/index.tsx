import { Suspense, lazy } from "react";
import { useLocation } from "react-router-dom";
import Landing from "../LandingPage";
import { LoadingPage } from "../LoadingPage";

const AuthenticatedAppShell = lazy(
  () => import("./components/AuthenticatedAppShell"),
);

export function AppWrapperPage() {
  const { pathname } = useLocation();

  // Render the marketing landing page when visitor hits the root route
  // regardless of authentication status
  if (pathname === "/") {
    return <Landing />;
  }

  return (
    <Suspense fallback={<LoadingPage />}>
      <AuthenticatedAppShell />
    </Suspense>
  );
}
