import { Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import ContextWrapper from "@/contexts";
import { ProtectedLoginRoute } from "@/components/authorization/authLoginGuard";
import { LoadingPage } from "@/pages/LoadingPage";
import LandingPage from "@/pages/LandingPage";
import { LoginPage } from "@/clerk/login-pages";
import OrganizationPage from "@/clerk/OrganizationPage";

export default function ShellApp() {
  return (
    <ContextWrapper>
      <Suspense fallback={<LoadingPage />}>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route
            path="/login"
            element={
              <ProtectedLoginRoute>
                <LoginPage />
              </ProtectedLoginRoute>
            }
          />
          <Route
            path="/organization"
            element={
              <ProtectedLoginRoute>
                <OrganizationPage />
              </ProtectedLoginRoute>
            }
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    </ContextWrapper>
  );
}
