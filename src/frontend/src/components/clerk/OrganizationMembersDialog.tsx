import {
  OrganizationProfile,
  useOrganization,
  useUser,
} from "@clerk/clerk-react";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";

type OrganizationMembersDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
};

export function OrganizationMembersDialog({
  open,
  onOpenChange,
}: OrganizationMembersDialogProps) {
  const { organization, isLoaded: isOrganizationLoaded } = useOrganization();
  const { user, isLoaded: isUserLoaded } = useUser();

  if (!IS_CLERK_AUTH) return null;

  const userId = isUserLoaded ? user?.id : undefined;
  const orgId = isOrganizationLoaded ? organization?.id : undefined;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-5xl">
        <DialogHeader>
          <DialogTitle>Members</DialogTitle>
          <DialogDescription>
            Manage members and quickly copy the current user and organization IDs.
          </DialogDescription>
        </DialogHeader>

        <div className="grid gap-3 rounded-lg border bg-muted/40 px-4 py-3 text-sm sm:grid-cols-2">
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              User ID
            </p>
            <p className="font-mono break-all text-foreground">
              {userId ?? (isUserLoaded ? "Unavailable" : "Loading...")}
            </p>
          </div>
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Org ID
            </p>
            <p className="font-mono break-all text-foreground">
              {orgId ?? (isOrganizationLoaded ? "Unavailable" : "Loading...")}
            </p>
          </div>
        </div>

        <div className="rounded-lg border shadow-sm">
          <OrganizationProfile
            routing="hash"
            appearance={{
              elements: {
                rootBox: "shadow-none border-0",
                card: "shadow-none border-0",
              },
            }}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default OrganizationMembersDialog;
