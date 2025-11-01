import { Navigate, type NavigateProps, useParams } from "react-router-dom";
import { ENABLE_CUSTOM_PARAM } from "../feature-flags";
import { navigateWithReload, shouldForceReload } from "@/utils/split-navigation";

export function CustomNavigate({ to, ...props }: NavigateProps) {
  const { customParam } = useParams();

  if (typeof to === "number") {
    return <Navigate to={to} {...props} />;
  }

  const target =
    ENABLE_CUSTOM_PARAM && typeof to === "string" && to.startsWith("/")
      ? `/${customParam}${to}`
      : to;

  if (shouldForceReload(target)) {
    navigateWithReload(target, props.replace);
    return null;
  }

  return <Navigate to={target} {...props} />;
}
