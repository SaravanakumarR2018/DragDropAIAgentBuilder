import { OrganizationProfile, UserButton } from "@clerk/clerk-react";
import { IS_CLERK_AUTH, useLogout } from "@/clerk/auth";
import useAuthStore from "@/stores/authStore";
import { LogOut, Users } from "lucide-react";
import { AccountMenu } from "@/components/core/appHeaderComponent/components/AccountMenu";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { useEffect, useState } from "react";

export function ClerkAccountMenu() {
  const { mutate: mutationLogout } = useLogout();
  const [isOrganizationProfileOpen, setIsOrganizationProfileOpen] = useState(false);
  const isAdmin = useAuthStore((state) => state.isAdmin);

  useEffect(() => {
    if (!isAdmin) {
      setIsOrganizationProfileOpen(false);
    }
  }, [isAdmin]);

  const handleLogout = () => {
    mutationLogout();
  };

  const handleOpenOrganizationProfile = () => {
    setIsOrganizationProfileOpen(true);
  };

  return IS_CLERK_AUTH ? (
    <div className="flex items-center gap-x-3">
      <UserButton
        appearance={{
          elements: {
            avatarBox: "h-6 w-6",
            userButtonPopoverActionButton__signOut: "hidden",
          },
        }}
      >
        <UserButton.MenuItems>
          <UserButton.Action label="manageAccount" />
          {isAdmin && (
            <UserButton.Action
              label="Members"
              labelIcon={<Users className="h-4 w-4" />}
              onClick={handleOpenOrganizationProfile}
            />
          )}
          <UserButton.Action
            label="Sign out"
            labelIcon={<LogOut className="h-4 w-4" />}
            onClick={handleLogout}
          />
        </UserButton.MenuItems>
      </UserButton>
      <AccountMenu />
      {isAdmin && (
        <Dialog
          open={isOrganizationProfileOpen}
          onOpenChange={setIsOrganizationProfileOpen}
        >
          <DialogContent className="max-w-3xl overflow-hidden p-0" hideTitle>
            <OrganizationProfile routing="virtual" />
          </DialogContent>
        </Dialog>
      )}
    </div>
  ) : (
    <AccountMenu />
  );
}

export default ClerkAccountMenu;