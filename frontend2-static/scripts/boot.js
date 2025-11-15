import { captureRedirectParam, getStoredRedirectPath } from "./redirect-utils.js";
import { getAuthSnapshot, isAuthenticated } from "./storage-sync.js";

const BASE_PATH = "/new/landingpage";
const AUTH_PAGES = new Set(["/", "/login", "/signup", "/organisation"]);

function normalisePath(pathname) {
  if (!pathname.startsWith(BASE_PATH)) return pathname;
  const suffix = pathname.slice(BASE_PATH.length) || "/";
  return suffix;
}

function redirect(to) {
  window.location.replace(to);
}

function guardRoutes() {
  if (!window.location.pathname.startsWith(BASE_PATH)) {
    captureRedirectParam();
    return;
  }

  captureRedirectParam();
  const suffix = normalisePath(window.location.pathname);
  const authState = getAuthSnapshot();
  const loggedIn = Boolean(authState.accessToken);
  const orgSelected = authState.isOrgSelected;

  if (!loggedIn) {
    if (suffix === "/dashboard") {
      redirect(`${BASE_PATH}/login`);
    }
    return;
  }

  if (!orgSelected && suffix !== "/organisation") {
    redirect(`${BASE_PATH}/organisation`);
    return;
  }

  if (orgSelected && AUTH_PAGES.has(suffix) && suffix !== "/dashboard") {
    redirect(`${BASE_PATH}/dashboard`);
  }
}

function announceStoredRedirect() {
  const path = getStoredRedirectPath();
  if (path) {
    console.debug("[frontend2] Stored redirect target", path);
  }
}

try {
  guardRoutes();
  announceStoredRedirect();
} catch (error) {
  console.error("[frontend2] Boot error", error);
}

export { isAuthenticated };
