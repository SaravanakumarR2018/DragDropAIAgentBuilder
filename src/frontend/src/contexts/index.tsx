import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReactFlowProvider } from "@xyflow/react";
import { ReactNode } from "react";
import { GradientWrapper } from "@/components/common/GradientWrapper";
import { CustomWrapper } from "@/customization/custom-wrapper";
import { AuthBroadcastListener } from "@/components/AuthBroadcastListener";
import { TooltipProvider } from "../components/ui/tooltip";
import { ApiInterceptor } from "../controllers/API/api";
import { AuthProvider } from "./authContext";
import { ClerkAuthAdapter, IS_CLERK_AUTH } from "@/clerk/auth";

// Export queryClient for use in utility functions (e.g., messageUtils, buildUtils)
export const queryClient = new QueryClient();

export default function ContextWrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient();

  // Element to wrap all context providers
  return (
    <CustomWrapper>
      <GradientWrapper>
        <QueryClientProvider client={queryClient}>
          <AuthProvider>
            {IS_CLERK_AUTH && <ClerkAuthAdapter />}
            <AuthBroadcastListener />
            <TooltipProvider skipDelayDuration={0}>
              <ReactFlowProvider>
                <ApiInterceptor />
                {children}
              </ReactFlowProvider>
            </TooltipProvider>
          </AuthProvider>
        </QueryClientProvider>
      </GradientWrapper>
    </CustomWrapper>
  );
}