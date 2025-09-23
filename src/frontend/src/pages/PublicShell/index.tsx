import { CustomNavigate } from "@/customization/components/custom-navigate";
import { ENABLE_CUSTOM_PARAM } from "@/customization/feature-flags";
import Landing from "@/pages/LandingPage";
import useAuthStore from "@/stores/authStore";
import type { JSX } from "react";
import { Outlet, useParams } from "react-router-dom";

export function PublicShell(): JSX.Element {
  return <Outlet />;
}

export function PublicLandingRoute(): JSX.Element {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const { customParam } = useParams();

  if (isAuthenticated) {
    const flowsPath =
      ENABLE_CUSTOM_PARAM && customParam
        ? `/${customParam}/flows`
        : "/flows";

    return <CustomNavigate replace to={flowsPath} />;
  }

  return <Landing />;
}
