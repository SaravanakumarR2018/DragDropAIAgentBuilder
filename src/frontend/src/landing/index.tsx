import ReactDOM from "react-dom/client";

import "../style/classes.css";
import "../style/index.css";
import "../style/applies.css";

import AppWithProvider from "@/clerk/auth";
import { LandingApp } from "./LandingApp";

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

root.render(
  <AppWithProvider>
    <LandingApp />
  </AppWithProvider>,
);
