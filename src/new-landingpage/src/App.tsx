import { Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { LoginPage } from "@/clerk/login-pages";
import { ProtectedLoginRoute } from "@/components/authorization/authLoginGuard";
import ContextWrapper from "@/contexts";
import { LoadingPage } from "@/pages/LoadingPage";
import LandingHome from "./LandingHome";
import "./App.css";

function LoginShell() {
  return (
    <ContextWrapper>
      <Suspense fallback={<LoadingPage />}>
        <ProtectedLoginRoute>
          <LoginPage />
        </ProtectedLoginRoute>
      </Suspense>
    </ContextWrapper>
  );
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingHome />} />
      <Route path="/login" element={<LoginShell />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
