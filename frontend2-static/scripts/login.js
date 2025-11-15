import "./boot.js";
import { loadClerk } from "./clerk-loader.js";
import { isAuthenticated } from "./boot.js";
import { clearAuthSession } from "./storage-sync.js";

const SIGN_IN_SELECTOR = "#clerk-sign-in";
const AFTER_SIGN_IN_URL = "/new/landingpage/organisation";
const SIGN_UP_URL = "/new/landingpage/signup";

function renderError(message) {
  const host = document.querySelector(SIGN_IN_SELECTOR);
  if (host) {
    host.innerHTML = `<div class="auth-error">${message}</div>`;
  }
}

async function initialise() {
  const host = document.querySelector(SIGN_IN_SELECTOR);
  if (!host) return;

  try {
    const clerk = await loadClerk();

    if (isAuthenticated()) {
      // Ensure we start fresh if the browser already has Langflow tokens but Clerk session is stale
      const session = clerk.session;
      if (!session) {
        console.warn("[login] Clearing stale Langflow session");
        clearAuthSession();
      }
    }

    if (clerk.session && clerk.session.status === "active") {
      console.debug("[login] Clerk session already active; redirecting to organisation");
      window.location.replace(AFTER_SIGN_IN_URL);
      return;
    }

    clerk.mountSignIn(host, {
      afterSignInUrl: AFTER_SIGN_IN_URL,
      afterSignUpUrl: AFTER_SIGN_IN_URL,
      signUpUrl: SIGN_UP_URL,
    });
  } catch (error) {
    console.error("[login] Unable to initialise Clerk", error);
    renderError(
      "We couldn't load the sign-in widget. Check your Clerk publishable key and try again."
    );
  }
}

initialise();
