import { SignIn, SignedIn, SignedOut, useAuth } from "@clerk/clerk-react";
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";

export default function NewLandingPageLogin() {
  const { isSignedIn } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    if (isSignedIn) {
      navigate("/organization", { replace: true });
    }
  }, [isSignedIn, navigate]);

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
            path="/new/landingpage/login"
            routing="path"
            afterSignInUrl="/new/landingpage/organization"
            redirectUrl="/new/landingpage/organization"
          />
        </SignedOut>
        <SignedIn>
          <div style={{ textAlign: "center" }}>Redirecting you to your organization list…</div>
        </SignedIn>
      </div>
    </div>
  );
}