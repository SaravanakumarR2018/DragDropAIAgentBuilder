import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

import "./index.css";
import "@/style/classes.css";
import "@/style/index.css";
import "@/App.css";
import "@/style/applies.css";

const root = document.getElementById("root");

if (!root) {
  throw new Error("Root element not found");
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
