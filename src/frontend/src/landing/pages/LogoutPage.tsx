import { useEffect } from "react";

import { useLogout } from "@/clerk/auth";
import { LoadingPage } from "@/pages/LoadingPage";
import { CustomNavigate } from "@/customization/components/custom-navigate";

export default function LogoutPage() {
  const { mutate, isSuccess } = useLogout({
    onSuccess: () => {
      sessionStorage.removeItem("isOrgSelected");
    },
  });

  useEffect(() => {
    mutate();
  }, [mutate]);

  if (isSuccess) {
    return <CustomNavigate to="/login" replace />;
  }

  return <LoadingPage />;
}
