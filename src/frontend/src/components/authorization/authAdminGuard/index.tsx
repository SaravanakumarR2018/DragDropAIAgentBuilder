import { useContext, useEffect, useRef, useState } from "react";
import { AuthContext } from "@/contexts/authContext";
import { CustomNavigate } from "@/customization/components/custom-navigate";
import { LoadingPage } from "@/pages/LoadingPage";
import useAuthStore from "@/stores/authStore";
import { useGetUserData } from "@/controllers/API/queries/auth";

export const ProtectedAdminRoute = ({ children }) => {
  const { userData, getUser } = useContext(AuthContext);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const isAdmin = useAuthStore((state) => state.isAdmin);
  const hasRequestedUser = useRef(false);
  const isSuperUser = userData?.is_superuser ?? isAdmin;
  const [userFetchFailed, setUserFetchFailed] = useState(false);
  const { mutate: fetchUserData } = useGetUserData({
    onError: () => {
      setUserFetchFailed(true);
    },
  });

  useEffect(() => {
    if (isAuthenticated && !userData && !hasRequestedUser.current) {
      hasRequestedUser.current = true;
      fetchUserData();
      getUser();
    }
  }, [fetchUserData, getUser, isAuthenticated, userData]);

  if (!isAuthenticated) {
    return <LoadingPage />;
  }

  if (!userData) {
    return <LoadingPage />;
  }

  if (!isSuperUser) {
    return <CustomNavigate to="/flows" replace />;
  }

  if (userFetchFailed) {
    return <CustomNavigate to="/flows" replace />;
  }

  return children;
};
