import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import ShellApp from "./ShellApp";
import AppWithProvider from "@/clerk/auth";
import { BASENAME } from "@/customization/config-constants";

import "@/style/classes.css";
import "@/style/index.css";
import "@/App.css";
import "@/style/applies.css";

const rootElement = document.getElementById("root");
if (!rootElement) {
  throw new Error("Root element not found");
}

ReactDOM.createRoot(rootElement).render(
  <BrowserRouter basename={BASENAME || undefined}>
    <AppWithProvider>
      <ShellApp />
    </AppWithProvider>
  </BrowserRouter>,
);
