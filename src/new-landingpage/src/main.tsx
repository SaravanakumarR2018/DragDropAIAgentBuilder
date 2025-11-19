import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import AppWithProvider from "@/clerk/auth";
import App from "./App";
import "./index.css";
import "@/style/classes.css";
import "@/style/index.css";
import "@/App.css";
import "@/style/applies.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AppWithProvider>
      <BrowserRouter basename="/new/landingpage">
        <App />
      </BrowserRouter>
    </AppWithProvider>
  </React.StrictMode>
);
