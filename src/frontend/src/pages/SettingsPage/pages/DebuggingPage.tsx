import { IS_CLERK_AUTH } from "@/clerk/auth";
import ForwardedIconComponent from "@/components/common/genericIconComponent";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useOrganization, useUser } from "@clerk/clerk-react";

function ClerkDebuggingContent() {
  const { user, isLoaded: isUserLoaded } = useUser();
  const { organization, isLoaded: isOrganizationLoaded } = useOrganization();

  const userId = isUserLoaded ? user?.id ?? "Unavailable" : "Loading...";
  const orgId = isOrganizationLoaded
    ? organization?.id ?? "No active organization"
    : "Loading...";

  return (
    <div className="flex h-full w-full flex-col gap-6">
      <div className="flex w-full flex-col gap-2">
        <h2 className="flex items-center text-lg font-semibold tracking-tight">
          Debugging
          <ForwardedIconComponent
            name="Bug"
            className="ml-2 h-5 w-5 text-primary"
          />
        </h2>
        <p className="text-sm text-muted-foreground">
          Inspect the Clerk identifiers currently in use to help troubleshoot
          authentication or organization access.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card className="h-full bg-card/60 backdrop-blur">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>User ID</CardTitle>
                <CardDescription>
                  Unique identifier for the signed-in Clerk user.
                </CardDescription>
              </div>
              <Badge variant="outline" className="font-normal">
                {isUserLoaded ? "Loaded" : "Pending"}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between rounded-md border border-border bg-background/80 px-3 py-2 font-mono text-sm">
              <span className="truncate" title={userId}>
                {userId}
              </span>
            </div>
          </CardContent>
        </Card>

        <Card className="h-full bg-card/60 backdrop-blur">
          <CardHeader>
            <div className="flex items-center justify-between">
              <div>
                <CardTitle>Organization ID</CardTitle>
                <CardDescription>
                  Active organization identifier from Clerk.
                </CardDescription>
              </div>
              <Badge variant="outline" className="font-normal">
                {isOrganizationLoaded ? "Loaded" : "Pending"}
              </Badge>
            </div>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between rounded-md border border-border bg-background/80 px-3 py-2 font-mono text-sm">
              <span className="truncate" title={orgId}>
                {orgId}
              </span>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function NonClerkDebuggingMessage() {
  return (
    <div className="flex h-full w-full flex-col gap-4">
      <div className="flex items-center gap-2">
        <ForwardedIconComponent
          name="ShieldOff"
          className="h-5 w-5 text-muted-foreground"
        />
        <h2 className="text-lg font-semibold tracking-tight">Debugging</h2>
      </div>
      <Card className="bg-card/60 backdrop-blur">
        <CardHeader>
          <CardTitle>Clerk not enabled</CardTitle>
          <CardDescription>
            This workspace is not configured to use Clerk authentication, so no
            Clerk identifiers are available.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

export default function DebuggingPage() {
  if (!IS_CLERK_AUTH) {
    return <NonClerkDebuggingMessage />;
  }

  return <ClerkDebuggingContent />;
}
