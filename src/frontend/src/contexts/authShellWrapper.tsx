import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactNode, useState } from "react";
import { AuthBroadcastListener } from "@/components/AuthBroadcastListener";
import { CustomWrapper } from "@/customization/custom-wrapper";
import { ApiInterceptor } from "@/controllers/API/api";
import { ClerkAuthAdapter, IS_CLERK_AUTH } from "@/clerk/auth";
import { GradientWrapper } from "@/components/common/GradientWrapper";
import { AuthProvider } from "./authContext";

export function AuthShellWrapper({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient());

  return (
    <CustomWrapper>
      <GradientWrapper>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>
            {IS_CLERK_AUTH && <ClerkAuthAdapter />}
            <AuthBroadcastListener />
            <ApiInterceptor />
            {children}
          </AuthProvider>
        </QueryClientProvider>
      </GradientWrapper>
    </CustomWrapper>
  );
}
