import { useContext, useEffect, useMemo, useState } from "react";
import { AuthContext } from "@/contexts/authContext";
import { CustomLoadingPage } from "@/customization/components/custom-loading-page";
import BillingPage from "@/pages/BillingPage";
import useAuthStore from "@/stores/authStore";

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

  const hasTrialAccess = useMemo(() => {
    if (!userData?.optins) {
      return false;
    }

    const { skip_trial_access: skipTrial, trial_access_until: trialUntil } =
      userData.optins;
    if (skipTrial) {
      return true;
    }
    if (!trialUntil) {
      return false;
    }
    const trialDate = new Date(trialUntil);
    if (Number.isNaN(trialDate.getTime())) {
      return false;
    }
    return trialDate.getTime() > Date.now();
  }, [userData?.optins]);

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
