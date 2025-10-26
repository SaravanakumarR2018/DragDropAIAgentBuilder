import ReactDOM from "react-dom/client";
import { Suspense, lazy } from "react";
import reportWebVitals from "./reportWebVitals";

import "./style/classes.css";
// @ts-ignore
import "./style/index.css";
// @ts-ignore
import "./style/applies.css";

// Load the marketing landing page and loading spinner synchronously.
import LandingPage from "./pages/LandingPage";
import { LoadingPage } from "./pages/LoadingPage";

// Create the root element once.
const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

// If the visitor is on the root path, render only the landing page without
// pulling in the full app bundle. Otherwise, defer loading heavy modules
// until needed using React.lazy and Suspense.
if (
  window.location.pathname === "/" ||
  window.location.pathname === "/index.html"
) {
  root.render(<LandingPage />);
} else {
  const AppWithProvider = lazy(() =>
    import("./clerk/auth").then((module) => ({ default: module.default })),
  );
  const CustomApp = lazy(() => import("./customization/custom-App"));
  root.render(
    <Suspense fallback={<LoadingPage />}>
      <AppWithProvider>
        <CustomApp />
      </AppWithProvider>
    </Suspense>,
  );
}

// Continue reporting web vitals for both the landing page and the app.
reportWebVitals();
