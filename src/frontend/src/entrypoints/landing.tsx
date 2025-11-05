import React from "react";
import ReactDOM from "react-dom/client";
import Landing from "../pages/LandingPage";

import "../style/index.css";
import "../style/classes.css";
import "../style/applies.css";

const container = document.getElementById("root");

if (!container) {
  throw new Error("Landing root element not found");
}

ReactDOM.createRoot(container).render(<Landing />);
