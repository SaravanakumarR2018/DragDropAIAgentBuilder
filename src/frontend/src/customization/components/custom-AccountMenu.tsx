import { UserButton, useClerk } from "@clerk/clerk-react";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import { LogOut } from "lucide-react";
import { AccountMenu } from "@/components/core/appHeaderComponent/components/AccountMenu";

export function CustomAccountMenu() {
  const { signOut } = useClerk();
  return IS_CLERK_AUTH ? (
    <UserButton
      appearance={{
        elements: {
          avatarBox: "h-6 w-6",
          userButtonPopoverActionButton__signOut: "hidden",
        },
      }}
    >
      <UserButton.MenuItems>
        <UserButton.Action
          label="Sign out"
          labelIcon={<LogOut className="h-4 w-4" />}
          onClick={async () => {
            await signOut();
          }}
        />
      </UserButton.MenuItems>
    </UserButton>
  ) : (
    <AccountMenu />
  );
}

export default CustomAccountMenu;
