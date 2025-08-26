import { SignIn, SignUp as ClerkSignUp, SignedOut } from "@clerk/clerk-react";
import { lazy } from "react";
import { IS_CLERK_AUTH } from "@/clerk/auth";
// Clerk login page component
export function ClerkLoginPage() {
  return (
    <SignedOut>
      <div style={centeredStyle}>
        <SignIn
          path="/login"
          routing="path"
          afterSignInUrl="/"
        />
      </div>
    </SignedOut>
  );
}

// Clerk sign-up page component
export function ClerkSignUpPage() {
  return (
    <SignedOut>
      <div style={centeredStyle}>
        <ClerkSignUp
          path="/sign-up"
          routing="path"
          afterSignUpUrl="/"
        />
      </div>
    </SignedOut>
  );
}

// Original pages
import OriginalLoginPage from "../pages/LoginPage";
import OriginalSignUp from "../pages/SignUpPage";
const OriginalLoginAdminPage = lazy(() => import("../pages/AdminPage/LoginPage"));

export const LoginPage = IS_CLERK_AUTH ? ClerkLoginPage : OriginalLoginPage;
export const SignUp = IS_CLERK_AUTH ? ClerkSignUpPage : OriginalSignUp;
export const LoginAdminPage = IS_CLERK_AUTH ? ClerkLoginPage : OriginalLoginAdminPage;

const centeredStyle: React.CSSProperties = {
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  minHeight: "100vh",
};