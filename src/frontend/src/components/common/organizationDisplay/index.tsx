import { IS_CLERK_AUTH, useLogout } from "@/clerk/auth";
import { useOrganization } from "@clerk/clerk-react";
import { Building2, ChevronDown, LogOut } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import ShadTooltip from "@/components/common/shadTooltipComponent";

/**
 * Component that displays the organization name when Clerk authentication is enabled.
 * Shows the organization name with an icon, only visible when authenticated via Clerk.
 */
export function OrganizationDisplay() {
  const { organization, isLoaded } = useOrganization();
  const { mutate: mutationLogout } = useLogout();
  const [showSwitchModal, setShowSwitchModal] = useState(false);

  // Don't render if Clerk auth is not enabled
  if (!IS_CLERK_AUTH) {
    return null;
  }

  // Don't render if organization data is not loaded yet
  if (!isLoaded) {
    return null;
  }

  // Don't render if no organization is selected
  if (!organization) {
    return null;
  }

  const organizationImageUrl = organization.imageUrl;

  const handleLogout = () => {
    mutationLogout();
    setShowSwitchModal(false);
  };

  const handleStayInOrg = () => {
    setShowSwitchModal(false);
  };

  return (
    <>
      <div
        className="flex min-w-0 items-center gap-1.5 rounded-md bg-muted/30 px-2 py-1 transition-colors hover:bg-muted/50 sm:px-2.5"
        data-testid="organization-display"
      >
        <div className="flex h-6 w-6 shrink-0 items-center justify-center overflow-hidden rounded-sm border border-border bg-muted">
          {organizationImageUrl ? (
            <img
              src={organizationImageUrl}
              alt={`${organization.name} logo`}
              className="h-full w-full object-cover"
              loading="lazy"
            />
          ) : (
            <Building2 className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          )}
        </div>
        <ShadTooltip
          content={organization.name}
          side="bottom"
          delayDuration={300}
        >
          <span className="sr-only text-sm font-semibold text-foreground sm:not-sr-only sm:max-w-[200px] sm:truncate">
            {organization.name}
          </span>
        </ShadTooltip>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Organization options"
              className="h-6 w-6 p-0 text-muted-foreground hover:bg-muted/60"
            >
              <ChevronDown className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel className="font-semibold">
              {organization.name}
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => setShowSwitchModal(true)}
              className="cursor-pointer"
            >
              <LogOut className="mr-2 h-4 w-4" />
              <span>Switch Organisation</span>
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <Dialog open={showSwitchModal} onOpenChange={setShowSwitchModal}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Switch Organisation</DialogTitle>
            <DialogDescription>
              You need to sign out to switch organisation
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="flex gap-2 sm:gap-2">
            <Button variant="outline" onClick={handleStayInOrg}>
              Stay in current organisation
            </Button>
            <Button variant="default" onClick={handleLogout}>
              Sign out and switch
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default OrganizationDisplay;
