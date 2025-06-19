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

// Reminder: Ensure VITE_CLERK_PUBLISHABLE_KEY is set in your .env file for the frontend.
// e.g., VITE_CLERK_PUBLISHABLE_KEY="pk_test_YOUR_KEY_HERE"

const RootAppWrapper = () => {
  const clerkAuthEnabled = useClerkConfigStore((state) => state.clerkAuthEnabled);
  // Use Vite env variable for the publishable key
  const clerkPublishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY;

  if (clerkAuthEnabled && clerkPublishableKey) {
    return (
      <ClerkProvider
        publishableKey={clerkPublishableKey}
        // TODO: Consider adding navigate function from react-router-dom for better SPA navigation with Clerk
        // navigate={(to) => navigate(to)} where const navigate = useNavigate(); from react-router-dom
        // This would require RootAppWrapper to be inside Router context or pass navigate prop.
      >
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
