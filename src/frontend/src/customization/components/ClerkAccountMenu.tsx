import { UserButton, useClerk, useUser } from "@clerk/clerk-react";
import { IS_CLERK_AUTH, useLogout } from "@/clerk/auth";
import { LogOut, Users, Settings, User } from "lucide-react";
import { AccountMenu } from "@/components/core/appHeaderComponent/components/AccountMenu";
import { cn } from "@/utils/utils";
import useAuthStore from "@/stores/authStore";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { useState } from "react";
import ThemeButtons from "@/components/core/appHeaderComponent/components/ThemeButtons";

export function ClerkAccountMenu() {
  const { mutate: mutationLogout } = useLogout();
  const { openUserProfile, openOrganizationProfile } = useClerk();
  const { user } = useUser();
  const [menuOpen, setMenuOpen] = useState(false);
  const isAdmin = useAuthStore((state) => state.isAdmin);

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
        <div className="flex items-center gap-3 px-5 py-3 rounded-xl hover:bg-muted/20 transition">
          <img
            src={user?.imageUrl}
            alt="avatar"
            className="h-8 w-8 rounded-full border border-border/30"
          />
          <div className="flex flex-col">
            <span className="text-[15px] font-semibold text-foreground">
              {user?.fullName || user?.username || "User"}
            </span>
            <span className="text-xs text-muted-foreground truncate max-w-[200px]">
              {user?.primaryEmailAddress?.emailAddress}
            </span>
          </div>
        </div>

        {/* Menu Items */}
        <div className="pt-2 text-sm">
          {isAdmin ? (
            <div className="mx-4 mb-2 flex items-center justify-between rounded-md border border-border/40 bg-muted px-3 py-2 text-xs font-medium text-foreground">
              <span>You are an Admin</span>
              <span className="rounded-full bg-primary/10 px-2 py-0.5 text-[10px] uppercase tracking-wide text-primary">
                Admin
              </span>
            </div>
          ) : null}
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

          {/* Admin */}
          <DropdownMenuItem
            asChild
            className="flex items-center gap-3 px-5 py-3 rounded-lg hover:bg-muted/30 transition"
          >
            <a href="/admin" className="flex items-center gap-3">
              <span className="inline-flex h-4 w-4 items-center justify-center rounded-full bg-primary/10 text-[10px] font-semibold uppercase text-primary">
                A
              </span>
              Admin
            </a>
          </DropdownMenuItem>

          {/* Settings */}
          <DropdownMenuItem asChild>
            <a
              href="/settings"
              className="flex items-center gap-3 px-5 py-3 rounded-lg hover:bg-muted/30 transition"
            >
              <Settings className="h-4 w-4" />
              Settings
            </a>
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
