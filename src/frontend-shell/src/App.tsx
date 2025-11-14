import { Suspense, lazy } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import AppWithProvider from "@/clerk/auth";
import ContextWrapper from "@/contexts";
import { LoadingPage } from "@/pages/LoadingPage";
import { BASENAME } from "@/customization/config-constants";

const LandingPage = lazy(() => import("@/pages/LandingPage"));
const OrganizationPage = lazy(() => import("@/clerk/OrganizationPage"));
const LoginPage = lazy(() =>
  import("@/clerk/login-pages").then((module) => ({
    default: module.LoginPage,
  })),
);

export default function App() {
  const basename = BASENAME || undefined;

  return (
    <AppWithProvider>
      <ContextWrapper>
        <BrowserRouter basename={basename}>
          <Suspense fallback={<LoadingPage />}>
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<LoginPage />} />
              <Route path="/organization" element={<OrganizationPage />} />
              <Route path="*" element={<Navigate to="/login" replace />} />
            </Routes>
          </Suspense>
        </BrowserRouter>
      </ContextWrapper>
    </AppWithProvider>
  );
}
