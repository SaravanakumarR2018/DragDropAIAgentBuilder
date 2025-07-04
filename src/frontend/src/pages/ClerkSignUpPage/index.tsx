import { SignUp, useUser } from "@clerk/clerk-react";
import { useAddUser } from "@/controllers/API/queries/auth";
import { useEffect, useRef } from "react";

export default function ClerkSignUpPage() {
  const { isSignedIn, user } = useUser();
  const { mutate: addUser } = useAddUser();
  const created = useRef(false);

  useEffect(() => {
    if (!created.current && isSignedIn && user) {
      const username = user.username || user.primaryEmailAddress?.emailAddress;
      if (username) {
        addUser({ username, password: "" }, { onSettled: () => { created.current = true; } });
      }
    }
  }, [isSignedIn, user, addUser]);

  return <SignUp />;
}
