import { useContext, useEffect, useRef } from "react";
import { AuthContext } from "@/contexts/authContext";
import { CustomNavigate } from "@/customization/components/custom-navigate";
import { LoadingPage } from "@/pages/LoadingPage";
import useAuthStore from "@/stores/authStore";

export const ProtectedAdminRoute = ({ children }) => {
  const { userData, getUser } = useContext(AuthContext);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isAdmin = useAuthStore((state) => state.isAdmin);
  const hasRequestedUser = useRef(false);

  useEffect(() => {
    if (isAuthenticated && !userData && !hasRequestedUser.current) {
      hasRequestedUser.current = true;
      getUser();
    }
  }, [getUser, isAuthenticated, userData]);

  if (!isAuthenticated) {
    return <LoadingPage />;
  }

  if (!userData) {
    return <LoadingPage />;
  }

  if (!isAdmin) {
    return <CustomNavigate to="/flows" replace />;
  } else {
    return children;
  }
};
