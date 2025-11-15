const CLERK_SCRIPT_URL = "https://cdn.jsdelivr.net/npm/@clerk/clerk-js@latest";
const STORAGE_KEY = "lf-clerk-publishable-key";

function resolvePublishableKey() {
  const candidates = [
    () => document.querySelector('meta[name="clerk-publishable-key"]')?.content,
    () => window.CLERK_PUBLISHABLE_KEY,
    () => window.VITE_CLERK_PUBLISHABLE_KEY,
    () => window.__CLERK_PUBLISHABLE_KEY__,
    () => window?.__env__?.VITE_CLERK_PUBLISHABLE_KEY,
    () => window?.__ENV__?.VITE_CLERK_PUBLISHABLE_KEY,
    () => localStorage.getItem(STORAGE_KEY),
  ];

  for (const getter of candidates) {
    try {
      const value = getter();
      if (typeof value === "string" && value.trim().length > 0) {
        localStorage.setItem(STORAGE_KEY, value.trim());
        return value.trim();
      }
    } catch (error) {
      console.warn("[clerk-loader] Unable to read candidate key", error);
    }
  }

  throw new Error("Missing Clerk publishable key. Ensure it is exposed to window or meta tag.");
}

function injectScript(publishableKey) {
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
    script.addEventListener("load", () => resolve());
    script.addEventListener("error", () => reject(new Error("Failed to load Clerk script")));
    document.head.appendChild(script);
  });
}

let clerkPromise = null;

export async function loadClerk() {
  if (clerkPromise) return clerkPromise;
  clerkPromise = (async () => {
    const publishableKey = resolvePublishableKey();
    await injectScript(publishableKey);
    if (!window.Clerk) {
      throw new Error("Clerk failed to initialise");
    }
    return window.Clerk.load({ publishableKey });
  })();
  return clerkPromise;
}
