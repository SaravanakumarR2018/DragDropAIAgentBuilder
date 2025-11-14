import ReactDOM from "react-dom/client";

import "../src/style/classes.css";
// @ts-ignore
import "../src/style/index.css";
// @ts-ignore
import "../src/App.css";
import "../src/style/applies.css";

import AppWithProvider from "../src/clerk/auth";
import ShellApp from "./App";

const root = ReactDOM.createRoot(document.getElementById("root") as HTMLElement);

root.render(
  <AppWithProvider>
    <ShellApp />
  </AppWithProvider>,
);
