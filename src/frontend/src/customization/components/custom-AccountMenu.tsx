import { IS_CLERK_AUTH, useLogout } from "@/clerk/auth";
import { AccountMenu } from "@/components/core/appHeaderComponent/components/AccountMenu";
import { UserButton} from "@clerk/clerk-react";
import { LogOut } from "lucide-react";

export function CustomAccountMenu() {
  const { mutateAsync: logout } = useLogout();

  if (!IS_CLERK_AUTH) return <AccountMenu />;

  return (
    <div className="h-6 w-6">
      <UserButton
        appearance={{ elements: { avatarBox: "h-6 w-6" } }}
        userMenuItems={{
          signOut: {
            // override Clerk's sign out
            onClick: async () => {
              try {
                await logout(); // ✅ your logout logic
              } catch (err) {
                console.error("Logout failed:", err);
              }
            },
            label: "Sign out",
            icon: <LogOut className="h-4 w-4" />,
          },
        }}
      />
    </div>
  );
}

export default CustomAccountMenu;