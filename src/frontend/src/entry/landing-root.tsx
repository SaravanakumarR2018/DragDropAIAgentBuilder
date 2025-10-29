import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import AppWithProvider from "../clerk/auth";
import { BASENAME } from "../customization/config-constants";
import Landing from "../pages/LandingPage";
import "../pages/LandingPage/landing.css";

const landingQueryClient = new QueryClient();

export function mountLanding(rootElement: HTMLElement) {
  const root = ReactDOM.createRoot(rootElement);

  root.render(
    <BrowserRouter basename={BASENAME || undefined}>
      <QueryClientProvider client={landingQueryClient}>
        <AppWithProvider>
          <Landing />
        </AppWithProvider>
      </QueryClientProvider>
    </BrowserRouter>,
  );
}
