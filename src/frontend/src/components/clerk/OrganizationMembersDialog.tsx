import {
  OrganizationProfile,
  useOrganization,
  useUser,
} from "@clerk/clerk-react";
import { cn } from "@/utils/cn";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import { clerkAppearance } from "@/clerk/appearance";
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
      <DialogContent
        className={cn(
          "w-full",
          "sm:max-w-3xl max-w-lg", // responsive width
          "max-h-[90vh]", // always fits inside viewport
          "overflow-y-auto", // enable scrolling
          "p-4 sm:p-6" // responsive padding
        )}
      >
        <DialogHeader>
          <DialogTitle>Members</DialogTitle>
          <DialogDescription>
            Manage members and quickly copy the current user and organization IDs.
          </DialogDescription>
        </DialogHeader>

        {/* User + Org IDs */}
        <div
          className={cn(
            "grid gap-3 text-sm sm:grid-cols-2",
            "rounded-lg border bg-muted/40 px-4 py-3"
          )}
        >
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              User ID
            </p>
            <p className="font-mono break-all text-foreground select-all">
              {userId ?? (isUserLoaded ? "Unavailable" : "Loading...")}
            </p>
          </div>
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Org ID
            </p>
            <p className="font-mono break-all text-foreground select-all">
              {orgId ?? (isOrganizationLoaded ? "Unavailable" : "Loading...")}
            </p>
          </div>
        </div>

        {/* Organization profile (Scrollable) */}
        <div
          className={cn(
            "rounded-lg border shadow-sm",
            "overflow-hidden" // prevent internal overflow clipping
          )}
        >
          <OrganizationProfile
            routing="hash"
            appearance={{
              ...clerkAppearance,
              elements: {
                ...clerkAppearance.elements,
                rootBox: "shadow-none border-0 !w-full",
                card: "shadow-none border-0 !w-full",
                scrollBox: "!overflow-y-auto", // ensure Clerk internal scroll
              },
            }}
          />
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default OrganizationMembersDialog;
