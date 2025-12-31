import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { LANDING_BASENAME } from "./landingRoutes";
import NewLandingPageLogin from "./NewLandingPageLogin";
import OrganizationOnboarding from "./OrganizationOnboarding";
import "./App.css";
import DashboardPage from "./DashboardPage";
import LandingPage from "./LandingPage";

function RootRoute() {
  return <LandingPage />;
}

export default function App() {
  console.log(`[App] App mounted with basename ${LANDING_BASENAME}`);

  return (
    <BrowserRouter basename={LANDING_BASENAME}>
      <Routes>
        <Route path="/" element={<RootRoute />} />
        <Route path="/login" element={<NewLandingPageLogin />} />
        <Route path="/organization" element={<OrganizationOnboarding />} />
        <Route path="/dashboard" element={<DashboardPage />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
