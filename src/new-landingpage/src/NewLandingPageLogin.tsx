import { SignIn, SignedIn, SignedOut, useAuth } from "@clerk/clerk-react";
import { useEffect } from "react";
import { LANDING_BASENAME } from "./landingRoutes";
import {
  clearStoredOrgSelection,
} from "./session";

export default function NewLandingPageLogin() {
  const { isSignedIn, isLoaded } = useAuth();

  console.log("[NewLandingPageLogin] render", { isLoaded, isSignedIn });

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      clearStoredOrgSelection();
    }
  }, [isLoaded, isSignedIn]);

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      console.log("[NewLandingPageLogin] User signed in, redirecting to /flows");
      window.location.assign("/flows");
    }
  }, [isLoaded, isSignedIn]);

  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        minHeight: "100vh",
        padding: "1rem",
      }}
    >
      <div>
        <SignedOut>
          <SignIn
            afterSignInUrl={`${LANDING_BASENAME}/login`}
            redirectUrl={`${LANDING_BASENAME}/login`}
          />
        </SignedOut>
        <SignedIn>
          <div style={{ textAlign: "center" }}>Redirecting you to your workspace…</div>
        </SignedIn>
      </div>
    </div>
  );
}
