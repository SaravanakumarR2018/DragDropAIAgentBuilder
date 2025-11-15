const ACCESS_TOKEN_KEY = "access_token_lf";
const REFRESH_TOKEN_KEY = "refresh_token_lf";
const AUTO_LOGIN_KEY = "auto_login_lf";
const ACTIVE_ORG_KEY = "lf-active-org";
const ORG_SELECTED_FLAG = "isOrgSelected";

function setCookie(name, value, options = {}) {
  const attributes = {
    path: "/",
    sameSite: "Strict",
    secure: true,
    ...options,
  };

  let cookie = `${name}=${encodeURIComponent(value)}`;
  cookie += `; Path=${attributes.path}`;
  cookie += `; SameSite=${attributes.sameSite}`;
  if (attributes.secure) cookie += "; Secure";
  if (typeof attributes.maxAge === "number") {
    cookie += `; Max-Age=${Math.floor(attributes.maxAge)}`;
  }
  if (attributes.expires instanceof Date) {
    cookie += `; Expires=${attributes.expires.toUTCString()}`;
  }
  document.cookie = cookie;
}

function deleteCookie(name) {
  document.cookie = `${name}=; Path=/; Max-Age=0; SameSite=Strict; Secure`;
}

function readCookie(name) {
  return document.cookie
    .split(";")
    .map((chunk) => chunk.trim())
    .filter(Boolean)
    .map((chunk) => chunk.split("="))
    .find(([key]) => key === name)?.[1];
}

export function persistAuthSession({
  accessToken,
  refreshToken,
  autoLoginValue = "login",
}) {
  if (!accessToken) return;
  try {
    setCookie(ACCESS_TOKEN_KEY, accessToken);
    localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
  } catch (error) {
    console.warn("[storage-sync] Unable to persist access token", error);
  }

  if (refreshToken) {
    try {
      setCookie(REFRESH_TOKEN_KEY, refreshToken);
    } catch (error) {
      console.warn("[storage-sync] Unable to persist refresh token", error);
    }
  }

  if (autoLoginValue) {
    try {
      setCookie(AUTO_LOGIN_KEY, autoLoginValue);
    } catch (error) {
      console.warn("[storage-sync] Unable to persist auto-login flag", error);
    }
  }
}

export function markOrganisationSelected(orgId) {
  try {
    sessionStorage.setItem(ORG_SELECTED_FLAG, "true");
  } catch (error) {
    console.warn("[storage-sync] Unable to set organisation flag", error);
  }

  if (!orgId) return;
  try {
    localStorage.setItem(ACTIVE_ORG_KEY, orgId);
  } catch (error) {
    console.warn("[storage-sync] Unable to persist organisation id", error);
  }
}

export function clearOrganisationSelection() {
  try {
    sessionStorage.removeItem(ORG_SELECTED_FLAG);
  } catch (error) {
    console.warn("[storage-sync] Unable to clear organisation flag", error);
  }
  try {
    localStorage.removeItem(ACTIVE_ORG_KEY);
  } catch (error) {
    console.warn("[storage-sync] Unable to clear organisation id", error);
  }
}

export function clearAuthSession() {
  deleteCookie(ACCESS_TOKEN_KEY);
  deleteCookie(REFRESH_TOKEN_KEY);
  deleteCookie(AUTO_LOGIN_KEY);
  try {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
  } catch (error) {
    console.warn("[storage-sync] Unable to clear access token", error);
  }
  clearOrganisationSelection();
}

export function getAuthSnapshot() {
  const accessToken = readCookie(ACCESS_TOKEN_KEY) || localStorage.getItem(ACCESS_TOKEN_KEY);
  const refreshToken = readCookie(REFRESH_TOKEN_KEY);
  let isOrgSelected = false;
  try {
    isOrgSelected = sessionStorage.getItem(ORG_SELECTED_FLAG) === "true";
  } catch (error) {
    console.warn("[storage-sync] Unable to read org flag", error);
  }
  let activeOrgId = null;
  try {
    activeOrgId = localStorage.getItem(ACTIVE_ORG_KEY);
  } catch (error) {
    console.warn("[storage-sync] Unable to read org id", error);
  }
  return {
    accessToken,
    refreshToken,
    isOrgSelected,
    activeOrgId,
  };
}

export function isAuthenticated() {
  const { accessToken } = getAuthSnapshot();
  return Boolean(accessToken);
}
