import { Suspense, lazy } from "react";
import ReactDOM from "react-dom/client";

import reportWebVitals from "./reportWebVitals";

// Import only the minimal styles needed for the landing page.  We avoid
// importing App.css here because it brings in Tailwind base/components for
// the flow builder and other authenticated pages.  These styles are now
// loaded in App.tsx, so they aren't included in the landing-page bundle.
import "./style/classes.css";
import "./style/index.css";
import "./style/applies.css";

// @ts-ignore
import LandingPage from "./pages/LandingPage";
import { LoadingPage } from "./pages/LoadingPage";

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

// Route to specific pages based on the current pathname.  This ensures that
// authentication pages (login, signup, admin login, organization selection)
// load only their own code and avoid pulling in the full application bundle.
const pathname = window.location.pathname;
if (pathname === "/" || pathname === "/index.html") {
  // Landing page: no heavy modules required
  root.render(<LandingPage />);
} else if (pathname === "/login" || pathname === "/login/") {
  // Email/password login page
  const AppWithProvider = lazy(() =>
    import("./clerk/auth").then((m) => ({ default: m.default })),
  );
  const LoginPage = lazy(() =>
    import("./clerk/login-pages").then((m) => ({ default: m.LoginPage })),
  );
  root.render(
    <Suspense fallback={<LoadingPage />}>
      <AppWithProvider>
        <LoginPage />
      </AppWithProvider>
    </Suspense>,
  );
} else if (pathname === "/signup" || pathname === "/signup/") {
  // Sign-up page
  const AppWithProvider = lazy(() =>
    import("./clerk/auth").then((m) => ({ default: m.default })),
  );
  const SignUpPage = lazy(() =>
    import("./clerk/login-pages").then((m) => ({ default: m.SignUp })),
  );
  root.render(
    <Suspense fallback={<LoadingPage />}>
      <AppWithProvider>
        <SignUpPage />
      </AppWithProvider>
    </Suspense>,
  );
} else if (pathname === "/login/admin" || pathname === "/login/admin/") {
  // Admin login page
  const AppWithProvider = lazy(() =>
    import("./clerk/auth").then((m) => ({ default: m.default })),
  );
  const LoginAdminPage = lazy(() =>
    import("./clerk/login-pages").then((m) => ({ default: m.LoginAdminPage })),
  );
  root.render(
    <Suspense fallback={<LoadingPage />}>
      <AppWithProvider>
        <LoginAdminPage />
      </AppWithProvider>
    </Suspense>,
  );
} else if (pathname === "/organization" || pathname === "/organization/") {
  // Organization selection page
  const AppWithProvider = lazy(() =>
    import("./clerk/auth").then((m) => ({ default: m.default })),
  );
  const OrganizationPage = lazy(() =>
    import("./clerk/OrganizationPage").then((m) => ({ default: m.default })),
  );
  root.render(
    <Suspense fallback={<LoadingPage />}>
      <AppWithProvider>
        <OrganizationPage />
      </AppWithProvider>
    </Suspense>,
  );
} else {
  // All other pages: load the full application with router/flows etc.
  const AppWithProvider = lazy(() =>
    import("./clerk/auth").then((m) => ({ default: m.default })),
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

reportWebVitals();
