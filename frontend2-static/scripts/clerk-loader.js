import {
  CLERK_FRONTEND_API,
  CLERK_PUBLISHABLE_KEY,
  applyClerkConfigToWindow,
  getClerkFrontendApi,
  getClerkPublishableKey,
} from "./clerk-config.js";

const CLERK_SCRIPT_URL = "https://cdn.jsdelivr.net/npm/@clerk/clerk-js@latest";

function rememberResolvedConfig(publishableKey, frontendApi) {
  if (typeof window === "undefined") return;
  try {
    if (publishableKey && publishableKey !== CLERK_PUBLISHABLE_KEY) {
      window.localStorage.setItem("lf-clerk-publishable-key", publishableKey);
    }
    if (frontendApi && frontendApi !== CLERK_FRONTEND_API) {
      window.localStorage.setItem("lf-clerk-frontend-api", frontendApi);
    }
  } catch (error) {
    console.warn("[clerk-loader] Unable to persist Clerk settings", error);
  }
}

function resolvePublishableKey() {
  const publishableKey = getClerkPublishableKey();
  if (publishableKey) {
    return publishableKey;
  }

  throw new Error(
    "Missing Clerk publishable key. Ensure it is configured in scripts/clerk-config.js or exposed globally.",
  );
}

function resolveFrontendApi() {
  return getClerkFrontendApi();
}

function injectScript(publishableKey, frontendApi) {
  return new Promise((resolve, reject) => {
    if (window.Clerk) {
      resolve();
      return;
    }
    const existing = document.querySelector(`script[src="${CLERK_SCRIPT_URL}"]`);
    if (existing) {
      existing.addEventListener("load", () => resolve());
      existing.addEventListener("error", reject);
      return;
    }
    const script = document.createElement("script");
    script.src = CLERK_SCRIPT_URL;
    script.async = true;
    script.setAttribute("data-clerk-publishable-key", publishableKey);
    if (frontendApi) {
      script.setAttribute("data-clerk-frontend-api", frontendApi);
    }
    script.addEventListener("load", () => resolve());
    script.addEventListener("error", () => reject(new Error("Failed to load Clerk script")));
    document.head.appendChild(script);
  });
}

let clerkPromise = null;

export async function loadClerk() {
  applyClerkConfigToWindow();

  if (clerkPromise) return clerkPromise;
  clerkPromise = (async () => {
    const publishableKey = resolvePublishableKey();
    const frontendApi = resolveFrontendApi();
    await injectScript(publishableKey, frontendApi);
    if (!window.Clerk) {
      throw new Error("Clerk failed to initialise");
    }
    rememberResolvedConfig(publishableKey, frontendApi);
    const loadOptions = frontendApi
      ? { publishableKey, frontendApi }
      : { publishableKey };
    return window.Clerk.load(loadOptions);
  })();
  return clerkPromise;
}
