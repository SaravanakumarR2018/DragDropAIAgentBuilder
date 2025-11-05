import type { NavigateOptions, To } from "react-router-dom";

function isWindowAvailable(): window is Window & {
  __LANGFLOW_APP_VARIANT?: "auth" | "main";
  __LANGFLOW_SPLIT_AUTH__?: boolean;
} {
  return typeof window !== "undefined";
}

export function isSplitAuthEnabled(): boolean {
  return isWindowAvailable() && window.__LANGFLOW_SPLIT_AUTH__ === true;
}

export function isAuthShell(): boolean {
  return isWindowAvailable() && window.__LANGFLOW_APP_VARIANT === "auth";
}

function isAbsolutePath(to: string): boolean {
  return to.startsWith("/");
}

export function shouldForceReload(to: To | number): to is string {
  return (
    typeof to === "string" &&
    isAbsolutePath(to) &&
    isSplitAuthEnabled() &&
    isAuthShell()
  );
}

export function navigateWithReload(to: string, replace?: NavigateOptions["replace"]): void {
  if (!isWindowAvailable()) {
    return;
  }
  if (replace) {
    window.location.replace(to);
  } else {
    window.location.assign(to);
  }
}
