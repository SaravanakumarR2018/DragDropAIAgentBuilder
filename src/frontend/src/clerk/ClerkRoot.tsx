import { PropsWithChildren } from "react";
import { ClerkProvider } from "@clerk/clerk-react";
import { CLERK_PUBLISHABLE_KEY } from "./config";
import { ClerkAuthAdapter } from "./auth";

export function ClerkRoot({ children }: PropsWithChildren): JSX.Element {
  return (
    <ClerkProvider publishableKey={CLERK_PUBLISHABLE_KEY}>
      <ClerkAuthAdapter />
      {children}
    </ClerkProvider>
  );
}