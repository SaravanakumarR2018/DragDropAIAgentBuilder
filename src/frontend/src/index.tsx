import ReactDOM from "react-dom/client";
import reportWebVitals from "./reportWebVitals";
import React, { Suspense, lazy } from "react";

import "./style/classes.css";
// @ts-ignore
import "./style/index.css";
// @ts-ignore
import "./App.css";
import "./style/applies.css";

// @ts-ignore

import AppWithProvider from "./clerk/auth";
const CustomApp = lazy(() => import("./customization/custom-App"));

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

root.render(
  <AppWithProvider>
    <Suspense fallback={<>Loading Application...</>}>
      <CustomApp />
    </Suspense>
  </AppWithProvider>,
);
reportWebVitals();
