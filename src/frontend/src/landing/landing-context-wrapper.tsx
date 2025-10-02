import { PropsWithChildren, useRef } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";

import { GradientWrapper } from "@/components/common/GradientWrapper";
import { ClerkAuthAdapter, IS_CLERK_AUTH } from "@/clerk/auth";
import { CustomWrapper } from "@/customization/custom-wrapper";
import { TooltipProvider } from "@/components/ui/tooltip";
import { AuthProvider } from "@/contexts/authContext";
import { LandingApiInterceptor } from "./landing-api-interceptor";

export function LandingContextWrapper({ children }: PropsWithChildren) {
  const queryClientRef = useRef<QueryClient>();

  if (!queryClientRef.current) {
    queryClientRef.current = new QueryClient();
  }

  return (
    <CustomWrapper>
      <GradientWrapper>
        <QueryClientProvider client={queryClientRef.current}>
          <AuthProvider>
            {IS_CLERK_AUTH && <ClerkAuthAdapter />}
            <TooltipProvider skipDelayDuration={0}>
              <LandingApiInterceptor />
              {children}
            </TooltipProvider>
          </AuthProvider>
        </QueryClientProvider>
      </GradientWrapper>
    </CustomWrapper>
  );
}
