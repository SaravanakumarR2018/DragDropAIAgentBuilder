// TODO: Ensure @clerk/clerk-react is installed (e.g., npm install @clerk/clerk-react)
import { ClerkProvider } from "@clerk/clerk-react"; // Added import
import ReactDOM from "react-dom/client";
import reportWebVitals from "./reportWebVitals";
import useClerkConfigStore from "./stores/clerkConfigStore"; // Added import

import "./style/classes.css";
// @ts-ignore
import "./style/index.css";
// @ts-ignore
import "./App.css";
import "./style/applies.css";

// @ts-ignore
import App from "./customization/custom-App"; // Assuming custom-App is the correct App entry

const RootAppWrapper = () => {
  const clerkAuthEnabled = useClerkConfigStore((state) => state.clerkAuthEnabled);
  const clerkPublishableKey = useClerkConfigStore((state) => state.clerkPublishableKey);

  if (clerkAuthEnabled && clerkPublishableKey) {
    return (
      <ClerkProvider publishableKey={clerkPublishableKey}>
        <App />
      </ClerkProvider>
    );
  }
  return <App />;
};

const root = ReactDOM.createRoot(
  document.getElementById("root") as HTMLElement,
);

root.render(<RootAppWrapper />);
reportWebVitals();
