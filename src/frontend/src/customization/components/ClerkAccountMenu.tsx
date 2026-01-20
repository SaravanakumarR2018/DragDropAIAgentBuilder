import { UserButton, useClerk, useUser } from "@clerk/clerk-react";
import { IS_CLERK_AUTH, useLogout } from "@/clerk/auth";
import { LogOut, Users, Settings, User, Shield } from "lucide-react";
import { AccountMenu } from "@/components/core/appHeaderComponent/components/AccountMenu";
import { cn } from "@/utils/utils";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { useContext, useState } from "react";
import ThemeButtons from "@/components/core/appHeaderComponent/components/ThemeButtons";
import { AuthContext } from "@/contexts/authContext";
import { useCustomNavigate } from "@/customization/hooks/use-custom-navigate";

export function ClerkAccountMenu() {
  const { mutate: mutationLogout } = useLogout();
  const { openUserProfile, openOrganizationProfile } = useClerk();
  const { user } = useUser();
  const { userData } = useContext(AuthContext);
  const [menuOpen, setMenuOpen] = useState(false);
  const navigate = useCustomNavigate();

  const handleLogout = () => {
    mutationLogout();
  };

  const handleOpenOrgProfile = () => {
    if (openOrganizationProfile) {
      openOrganizationProfile();
    }
  };

  const handleOpenUserProfile = () => openUserProfile?.();

  return IS_CLERK_AUTH ? (
    <DropdownMenu open={menuOpen} onOpenChange={setMenuOpen}>
      <DropdownMenuTrigger asChild>
        <div className="flex items-center gap-3 cursor-pointer">
          <UserButton
            appearance={{
              elements: {
                avatarBox: "h-7 w-7",
                userButtonPopoverActionButton__signOut: "hidden",
              },
            }}
          />
        </div>
      </DropdownMenuTrigger>

      <DropdownMenuContent
        align="end"
        className={cn(
          "w-[340px] md:w-[320px]",
          "rounded-2xl border border-border/20 bg-background/95 shadow-2xl backdrop-blur-xl",
          "divide-y divide-border/10 py-2 px-1"
        )}
      >
        {/* User Info */}
        <div className="flex flex-col gap-3 px-5 py-3 rounded-xl hover:bg-muted/20 transition">
          <div className="flex items-center gap-3">
            <img
              src={user?.imageUrl}
              alt="avatar"
              className="h-8 w-8 rounded-full border border-border/30"
            />
            <div className="flex flex-col flex-1">
              <span className="text-[15px] font-semibold text-foreground">
                {user?.fullName || user?.username || "User"}
              </span>
              <span className="text-xs text-muted-foreground truncate max-w-[200px]">
                {user?.primaryEmailAddress?.emailAddress}
              </span>
            </div>
          </div>
          {userData?.is_superuser && (
            <div className="flex items-center gap-2 text-amber-600">
              <Shield className="h-4 w-4" />
              <span className="text-xs font-semibold">You are an admin</span>
            </div>
          )}
        </div>

        {/* Menu Items */}
        <div className="pt-2 text-sm">
          {/* Manage Account */}
          <DropdownMenuItem
            onClick={handleOpenUserProfile}
            className="flex items-center gap-3 px-5 py-3 rounded-lg hover:bg-muted/30 transition"
          >
            <User className="h-4 w-4" />
            Manage Account
          </DropdownMenuItem>

          {/* Members */}
          <DropdownMenuItem
            onClick={handleOpenOrgProfile}
            className="flex items-center gap-3 px-5 py-3 rounded-lg hover:bg-muted/30 transition"
          >
            <Users className="h-4 w-4" />
            Members
          </DropdownMenuItem>

          {/* Admin Page */}
          {userData?.is_superuser && (
            <DropdownMenuItem
              onClick={() => navigate("/admin")}
              className="flex items-center gap-3 px-5 py-3 rounded-lg hover:bg-muted/30 transition"
            >
              <Shield className="h-4 w-4" />
              Admin Page
            </DropdownMenuItem>
          )}

          {/* Settings */}
          <DropdownMenuItem
            onClick={() => navigate("/settings")}
            className="flex items-center gap-3 px-5 py-3 rounded-lg hover:bg-muted/30 transition"
          >
            <Settings className="h-4 w-4" />
            Settings
          </DropdownMenuItem>

          {/* Theme */}
          <div className="flex items-center justify-between px-5 py-3 rounded-lg hover:bg-muted/30 transition">
            <span>Theme</span>
            <ThemeButtons />
          </div>
          {/* Logout */}
          <DropdownMenuItem
            onClick={handleLogout}
            className="flex items-center gap-3 px-5 py-3 mt-1 text-red-500 hover:bg-red-500/10 rounded-lg transition"
          >
            <LogOut className="h-4 w-4" />
            Logout
          </DropdownMenuItem>
        </div>
      </DropdownMenuContent>
    </DropdownMenu>
  ) : (
    <AccountMenu />
  );
}

export default ClerkAccountMenu;