const REDIRECT_STORAGE_KEY = "lf-sanitized-redirect";

function sanitizeRelativePath(path) {
  if (!path || typeof path !== "string") return null;
  const trimmed = path.trim();
  if (!trimmed.startsWith("/")) return null;
  if (trimmed.startsWith("//")) return null;
  const url = new URL(trimmed, window.location.origin);
  // Prevent open redirects
  if (url.origin !== window.location.origin) {
    return null;
  }
  return url.pathname + url.search + url.hash;
}

export function captureRedirectParam() {
  const params = new URLSearchParams(window.location.search);
  if (!params.has("redirect")) return null;
  const raw = params.get("redirect");
  params.delete("redirect");
  const nextSearch = params.toString();
  const cleanPath = sanitizeRelativePath(raw);
  const newUrl = `${window.location.pathname}${nextSearch ? `?${nextSearch}` : ""}${window.location.hash}`;
  window.history.replaceState({}, "", newUrl);
  if (cleanPath) {
    sessionStorage.setItem(REDIRECT_STORAGE_KEY, cleanPath);
  }
  return cleanPath;
}

export function getStoredRedirectPath() {
  try {
    return sessionStorage.getItem(REDIRECT_STORAGE_KEY);
  } catch (error) {
    console.warn("[redirect-utils] Unable to read redirect path", error);
    return null;
  }
}

export function consumeRedirectPath() {
  const current = getStoredRedirectPath();
  if (current) {
    try {
      sessionStorage.removeItem(REDIRECT_STORAGE_KEY);
    } catch (error) {
      console.warn("[redirect-utils] Unable to clear redirect path", error);
    }
  }
  return current;
}

export function setRedirectPath(path) {
  const cleanPath = sanitizeRelativePath(path);
  if (!cleanPath) return;
  try {
    sessionStorage.setItem(REDIRECT_STORAGE_KEY, cleanPath);
  } catch (error) {
    console.warn("[redirect-utils] Unable to persist redirect", error);
  }
}
