import ReactDOM from "react-dom/client";
import AppWithProvider from "../../frontend/src/clerk/auth";
import ShellRouter from "./shell-router";

import "../../frontend/src/style/classes.css";
// @ts-ignore - reuse compiled styles from main frontend
import "../../frontend/src/style/index.css";
// @ts-ignore - reuse global app styles
import "../../frontend/src/App.css";
import "../../frontend/src/style/applies.css";

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

root.render(
  <AppWithProvider>
    <ShellRouter />
  </AppWithProvider>,
);
