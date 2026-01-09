import { useContext, useEffect, useMemo, useState } from "react";
import { AuthContext } from "@/contexts/authContext";
import { CustomLoadingPage } from "@/customization/components/custom-loading-page";
import BillingPage from "@/pages/BillingPage";
import useAuthStore from "@/stores/authStore";
import { resolveHasAccess } from "@/utils/billing/hasAccess";

const TrialAccessGate = ({
  children,
}: {
  children: React.ReactNode;
}): React.ReactElement => {
  const { userData, getUser } = useContext(AuthContext);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const [requestStarted, setRequestStarted] = useState(false);

  useEffect(() => {
    if (!isAuthenticated || userData || requestStarted) {
      return;
    }
    setRequestStarted(true);
    getUser();
  }, [getUser, isAuthenticated, requestStarted, userData]);

  const hasTrialAccess = useMemo(
    () => resolveHasAccess(userData?.optins),
    [userData?.optins],
  );

  if (!isAuthenticated) {
    return <>{children}</>;
  }

  if (!userData) {
    return <CustomLoadingPage />;
  }

  if (!hasTrialAccess) {
    return <BillingPage />;
  }

  return <>{children}</>;
};

export default TrialAccessGate;
