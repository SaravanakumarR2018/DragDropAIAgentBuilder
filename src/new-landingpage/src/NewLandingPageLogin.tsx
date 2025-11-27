import { SignIn, SignedIn, SignedOut, useAuth } from "@clerk/clerk-react";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { LANDING_BASENAME } from "./landingRoutes";
import { ACTIVE_ORG_STORAGE_KEY, ORG_SELECTED_KEY } from "./session";

export default function NewLandingPageLogin() {
  const { isSignedIn, isLoaded } = useAuth();
  const navigate = useNavigate();

  console.log("[NewLandingPageLogin] render", { isLoaded, isSignedIn });

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      localStorage.removeItem(ORG_SELECTED_KEY);
      localStorage.removeItem(ACTIVE_ORG_STORAGE_KEY);

      console.log("[NewLandingPageLogin] User signed in, redirecting to organization");

      navigate("/organization", { replace: true });
    }
  }, [isLoaded, isSignedIn, navigate]);

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
            path={`${LANDING_BASENAME}/login`}
            routing="path"
            afterSignInUrl={`${LANDING_BASENAME}/login`}
            redirectUrl={`${LANDING_BASENAME}/login`}
          />
        </SignedOut>
        <SignedIn>
          <div style={{ textAlign: "center" }}>Redirecting you to your organization list…</div>
        </SignedIn>
      </div>
    </div>
  );
}