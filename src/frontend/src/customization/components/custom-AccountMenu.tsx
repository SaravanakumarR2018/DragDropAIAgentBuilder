import { IS_CLERK_AUTH, useLogout } from "@/clerk/auth";
import { AccountMenu } from "@/components/core/appHeaderComponent/components/AccountMenu";
import { UserButton} from "@clerk/clerk-react";
import { LogOut } from "lucide-react";

export function CustomAccountMenu() {
  const { mutateAsync: logout } = useLogout();

  if (!IS_CLERK_AUTH) return <AccountMenu />;

  return (
    <div className="h-6 w-6">
      <UserButton appearance={{ elements: { avatarBox: "h-6 w-6", userButtonPopoverActionButton__signOut: "hidden" } }}>
        <UserButton.MenuItems>
          <UserButton.Action
            label="Sign out"
            labelIcon={<LogOut className="w-4 h-4" />}
            onClick={async () => {
            try {
              await logout();
              } catch (err) {
              console.error("Logout failed:", err);
              }
            }}
          />
        </UserButton.MenuItems>
      </UserButton>
    </div>
  );
}

export default CustomAccountMenu;