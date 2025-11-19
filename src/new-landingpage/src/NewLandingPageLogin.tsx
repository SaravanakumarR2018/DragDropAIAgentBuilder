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
    <div className="login-shell">
      <div className="login-grid">
        <section className="login-card login-card--primary">
          <p className="login-eyebrow">Secure access</p>
          <h1 className="login-heading">Sign in to Visual AI Agents Builder</h1>
          <p className="login-subheading">
            Use your Clerk identity to authenticate and seamlessly sync with Langflow's backend.
          </p>
          <SignedOut>
            <SignIn
              path="/new/landingpage/login"
              routing="path"
              afterSignInUrl="/new/landingpage/organization"
              redirectUrl="/new/landingpage/organization"
            />
          </SignedOut>
          <SignedIn>
            <div className="login-status">Redirecting you to your organization list…</div>
          </SignedIn>
        </section>
      </div>
    </div>
  );
}
