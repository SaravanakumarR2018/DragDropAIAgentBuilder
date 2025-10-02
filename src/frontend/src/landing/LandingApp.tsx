import { Suspense } from "react";
import { RouterProvider } from "react-router-dom";

import { LoadingPage } from "@/pages/LoadingPage";
import { landingRouter } from "./landing-router";

export function LandingApp() {
  return (
    <Suspense fallback={<LoadingPage />}>
      <RouterProvider router={landingRouter} />
    </Suspense>
  );
}
