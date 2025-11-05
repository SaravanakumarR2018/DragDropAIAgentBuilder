import React from "react";
import ReactDOM from "react-dom/client";
import reportWebVitals from "../reportWebVitals";
import AppRoot from "../index";

import "../style/index.css";
import "../style/classes.css";
import "../style/applies.css";
import "../App.css";

const container = document.getElementById("root");

if (!container) {
  throw new Error("App root element not found");
}

const root = ReactDOM.createRoot(container);

root.render(<AppRoot />);

reportWebVitals();
