import ReactDOM from "react-dom/client";
import reportWebVitals from "./reportWebVitals";

import "./style/classes.css";
// @ts-ignore
import "./style/index.css";
// @ts-ignore
import "./App.css";
import "./style/applies.css";

// @ts-ignore
import App from "./customization/custom-App";
import { IS_CLERK_AUTH } from "./constants/constants";
import ClerkAuthProvider from "./clerk/clerk-provider";
import ContextWrapper from "./contexts";

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

root.render(
  IS_CLERK_AUTH ? (
    <ClerkAuthProvider>
      <App />
    </ClerkAuthProvider>
  ) : (
    <ContextWrapper>
      <App />
    </ContextWrapper>
  ),
);
reportWebVitals();
