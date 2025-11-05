import ReactDOM from "react-dom/client";
import reportWebVitals from "./reportWebVitals";

import "./style/classes.css";
// @ts-ignore
import "./style/index.css";
// @ts-ignore
import "./App.css";
import "./style/applies.css";

import AppWithProvider from "./clerk/auth";
import CustomAuthApp from "./customization/custom-AuthApp";

declare global {
  interface Window {
    __LANGFLOW_APP_VARIANT?: "auth" | "main";
    __LANGFLOW_SPLIT_AUTH__?: boolean;
  }
}

if (typeof window !== "undefined") {
  window.__LANGFLOW_APP_VARIANT = "auth";
  window.__LANGFLOW_SPLIT_AUTH__ =
    String(import.meta.env.VITE_SPLIT_AUTH_ROUTES ?? "false").toLowerCase() === "true";
}

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

root.render(
  <AppWithProvider>
    <CustomAuthApp />
  </AppWithProvider>,
);

reportWebVitals();
