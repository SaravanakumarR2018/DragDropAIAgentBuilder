import { IS_CLERK_AUTH, useLogout } from "@/clerk/auth";
import { useOrganization } from "@clerk/clerk-react";
import { Building2, ChevronDown, LogOut } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
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
  const [hasImageError, setHasImageError] = useState(false);

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
  const organizationInitials = useMemo(() => {
    if (!organization.name) {
      return "";
    }

    const [firstWord = "", secondWord = ""] = organization.name
      .split(/\s+/)
      .filter(Boolean);

    const firstInitial = firstWord.charAt(0) ?? "";
    const secondInitial = secondWord.charAt(0) ?? "";

    return `${firstInitial}${secondInitial}`.toUpperCase();
  }, [organization.name]);

  useEffect(() => {
    setHasImageError(false);
  }, [organizationImageUrl]);

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
        aria-label={organization.name}
      >
        <div className="flex h-6 w-6 shrink-0 items-center justify-center overflow-hidden rounded-full border border-border bg-muted">
          {organizationImageUrl && !hasImageError ? (
            <img
              src={organizationImageUrl}
              alt={`${organization.name} logo`}
              loading="lazy"
              crossOrigin="anonymous"
              referrerPolicy="no-referrer"
              className="h-full w-full object-cover"
              onError={() => setHasImageError(true)}
            />
          ) : organizationInitials ? (
            <span className="text-xs font-semibold text-muted-foreground">
              {organizationInitials}
            </span>
          ) : (
            <Building2 className="h-4 w-4 text-muted-foreground" aria-hidden="true" />
          )}
        </div>
        <span className="sr-only sm:hidden">{organization.name}</span>
        <ShadTooltip
          content={organization.name}
          side="bottom"
          delayDuration={300}
        >
          <span className="hidden min-w-0 text-sm font-semibold text-foreground sm:block sm:max-w-[200px] sm:truncate md:max-w-[240px]">
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
