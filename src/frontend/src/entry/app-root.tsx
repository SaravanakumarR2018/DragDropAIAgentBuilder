import ReactDOM from "react-dom/client";

import "../style/classes.css";
// @ts-ignore
import "../style/index.css";
// @ts-ignore
import "../App.css";
import "../style/applies.css";

import AppWithProvider from "../clerk/auth";
import CustomApp from "../customization/custom-App";
import reportWebVitals from "../reportWebVitals";

export function mountApp(rootElement: HTMLElement) {
  const root = ReactDOM.createRoot(rootElement);

  root.render(
    <AppWithProvider>
      <CustomApp />
    </AppWithProvider>,
  );

  reportWebVitals();
}
