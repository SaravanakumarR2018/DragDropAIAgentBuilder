import { IS_CLERK_AUTH } from "@/clerk/auth";
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
import { Button } from "@/components/ui/button";
import { useOrganization } from "@clerk/clerk-react";
import { useLogout as useAppLogout } from "@/controllers/API/queries/auth/use-post-logout";
import { Building2, ChevronDown, LogOut } from "lucide-react";
import { useState } from "react";

/**
 * Component that displays the organization name when Clerk authentication is enabled.
 * Shows the organization name with an icon, only visible when authenticated via Clerk.
 */
export function OrganizationDisplay() {
  if (!IS_CLERK_AUTH) {
    return null;
  }

  const { organization, isLoaded } = useOrganization();
  const { mutate: triggerAppLogout } = useAppLogout();
  const [isDialogOpen, setIsDialogOpen] = useState(false);

  // Don't render if organization data is not loaded yet
  if (!isLoaded) {
    return null;
  }

  // Don't render if no organization is selected
  if (!organization) {
    return null;
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button
            className="flex items-center gap-2 rounded-md bg-muted/30 px-3 py-1.5 text-sm font-semibold text-foreground transition-colors hover:bg-muted/60"
            data-testid="organization-display"
          >
            <Building2 className="h-4 w-4 text-primary" />
            <span className="max-w-[200px] truncate">{organization.name}</span>
            <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start" className="w-60">
          <DropdownMenuLabel className="flex items-center gap-2 text-sm">
            <Building2 className="h-4 w-4 text-primary" />
            <span className="max-w-[180px] truncate">{organization.name}</span>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem
            className="flex items-center gap-2 py-2 text-sm font-medium text-destructive focus:text-destructive"
            onSelect={(event) => {
              event.preventDefault();
              setIsDialogOpen(true);
            }}
          >
            <LogOut className="h-4 w-4" />
            <span>Switch organization</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Ready to switch organizations?</DialogTitle>
            <DialogDescription>
              To switch to a different organization, you&apos;ll need to sign out first.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="ghost"
              onClick={() => setIsDialogOpen(false)}
            >
              Stay in current organization
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                setIsDialogOpen(false);
                triggerAppLogout();
              }}
            >
              Sign out and switch
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default OrganizationDisplay;
