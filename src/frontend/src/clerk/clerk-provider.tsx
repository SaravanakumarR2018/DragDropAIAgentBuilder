import { ClerkProvider } from "@clerk/clerk-react";
import ContextWrapper from "@/contexts";
import { CLERK_PUBLISHABLE_KEY } from "@/constants/constants";
import ClerkAuthAdapter from "./clerk-auth-adapter";

export default function ClerkAuthProvider({ children }) {
  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
      <ClerkAuthAdapter />
      <ContextWrapper>{children}</ContextWrapper>
    </ClerkProvider>
  );
}
