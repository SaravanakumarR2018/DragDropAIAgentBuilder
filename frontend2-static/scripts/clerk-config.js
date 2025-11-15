const EXPLICIT_CLERK_CONFIG = Object.freeze({
  /**
   * Replace the empty string below with your Clerk publishable key during the build.
   * Example: "pk_test_123456789".
   */
  publishableKey: "",
  /**
   * Replace the empty string below with your Clerk frontend API (without protocol).
   * Example: "clerk.yourapp.dev".
   */
  frontendApi: "",
});

const STORAGE_KEY = "lf-clerk-publishable-key";
const FRONTEND_API_STORAGE_KEY = "lf-clerk-frontend-api";

function safeTrim(value) {
  return typeof value === "string" ? value.trim() : "";
}

function readFromLocalStorage(key) {
  try {
    return localStorage.getItem(key);
  } catch (error) {
    console.warn(`[clerk-config] Unable to access localStorage for ${key}`, error);
    return "";
  }
}

function writeToLocalStorage(key, value) {
  try {
    if (value) {
      localStorage.setItem(key, value);
    }
  } catch (error) {
    console.warn(`[clerk-config] Unable to persist ${key} in localStorage`, error);
  }
}

function coalesce(...values) {
  for (const value of values) {
    const trimmed = safeTrim(value);
    if (trimmed) return trimmed;
  }
  return "";
}

export function getExplicitClerkConfig() {
  return EXPLICIT_CLERK_CONFIG;
}

export function getClerkPublishableKey() {
  const explicit = safeTrim(EXPLICIT_CLERK_CONFIG.publishableKey);
  if (explicit) return explicit;

  if (typeof window === "undefined") {
    return "";
  }

  const candidates = [
    window.CLERK_PUBLISHABLE_KEY,
    window.VITE_CLERK_PUBLISHABLE_KEY,
    window.__CLERK_PUBLISHABLE_KEY__,
    window?.__env__?.VITE_CLERK_PUBLISHABLE_KEY,
    window?.__ENV__?.VITE_CLERK_PUBLISHABLE_KEY,
  ];

  if (typeof document !== "undefined") {
    candidates.push(
      document.querySelector('meta[name="clerk-publishable-key"]')?.content,
    );
  }

  candidates.push(readFromLocalStorage(STORAGE_KEY));

  return coalesce(...candidates);
}

export function getClerkFrontendApi() {
  const explicit = safeTrim(EXPLICIT_CLERK_CONFIG.frontendApi);
  if (explicit) return explicit;

  if (typeof window === "undefined") {
    return "";
  }

  const candidates = [
    window.CLERK_FRONTEND_API,
    window.__CLERK_FRONTEND_API__,
    window?.__env__?.VITE_CLERK_FRONTEND_API,
    window?.__ENV__?.VITE_CLERK_FRONTEND_API,
    readFromLocalStorage(FRONTEND_API_STORAGE_KEY),
  ];

  return coalesce(...candidates);
}

export function applyClerkConfigToWindow() {
  if (typeof window === "undefined") {
    return;
  }

  const publishableKey = getClerkPublishableKey();
  const frontendApi = getClerkFrontendApi();

  if (publishableKey) {
    window.CLERK_PUBLISHABLE_KEY = publishableKey;
    window.VITE_CLERK_PUBLISHABLE_KEY = publishableKey;
    window.__CLERK_PUBLISHABLE_KEY__ = publishableKey;
  }

  if (frontendApi) {
    window.CLERK_FRONTEND_API = frontendApi;
    window.__CLERK_FRONTEND_API__ = frontendApi;
  }

  if (typeof document !== "undefined") {
    const metaName = "clerk-publishable-key";
    let meta = document.querySelector(`meta[name="${metaName}"]`);
    if (!meta) {
      meta = document.createElement("meta");
      meta.name = metaName;
      document.head.appendChild(meta);
    }
    if (publishableKey) {
      meta.content = publishableKey;
    }
  }

  if (publishableKey) {
    writeToLocalStorage(STORAGE_KEY, publishableKey);
  }
  if (frontendApi) {
    writeToLocalStorage(FRONTEND_API_STORAGE_KEY, frontendApi);
  }
}

applyClerkConfigToWindow();

export const CLERK_PUBLISHABLE_KEY = getClerkPublishableKey();
export const CLERK_FRONTEND_API = getClerkFrontendApi();
