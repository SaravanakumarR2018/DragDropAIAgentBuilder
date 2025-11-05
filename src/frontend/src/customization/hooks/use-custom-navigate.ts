import {
  type NavigateFunction,
  type NavigateOptions,
  type To,
  useNavigate,
  useParams,
} from "react-router-dom";
import { ENABLE_CUSTOM_PARAM } from "../feature-flags";
import { navigateWithReload, shouldForceReload } from "@/utils/split-navigation";

export function useCustomNavigate(): NavigateFunction {
  const domNavigate = useNavigate();

  const { customParam } = useParams();

  function navigate(to: To | number, options?: NavigateOptions) {
    if (typeof to === "number") {
      domNavigate(to);
    } else {
      const target =
        ENABLE_CUSTOM_PARAM && to[0] === "/" ? `/${customParam}${to}` : to;

      if (shouldForceReload(target)) {
        navigateWithReload(target, options?.replace);
        return;
      }

      domNavigate(target, options);
    }
  }

  return navigate;
}
