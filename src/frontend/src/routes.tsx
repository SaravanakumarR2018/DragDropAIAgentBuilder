import { Suspense, lazy } from "react";
import { createBrowserRouter, Outlet } from "react-router-dom";
import { BASENAME } from "./customization/config-constants";
import { LoadingPage } from "./pages/LoadingPage";

const LandingPage = lazy(() => import("./pages/LandingPage"));

function LazyOutlet() {
  return <Outlet />;
}

const router = createBrowserRouter(
  [
    {
      path: "/",
      element: (
        <Suspense fallback={<LoadingPage />}>
          <LandingPage />
        </Suspense>
      ),
    },
    {
      path: "/*",
      lazy: async () => {
        const { getAppRoutes } = await import("./routes/app-routes.lazy");
        return {
          Component: LazyOutlet,
          children: getAppRoutes(),
        };
      },
    },
  ],
  { basename: BASENAME || undefined },
);

export default router;
