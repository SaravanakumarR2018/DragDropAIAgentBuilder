import "./boot.js";
import { loadClerk } from "./clerk-loader.js";

const SIGN_UP_SELECTOR = "#clerk-sign-up";
const AFTER_SIGN_UP_URL = "/new/landingpage/organisation";
const SIGN_IN_URL = "/new/landingpage/login";

function renderError(message) {
  const host = document.querySelector(SIGN_UP_SELECTOR);
  if (host) {
    host.innerHTML = `<div class="auth-error">${message}</div>`;
  }
}

async function initialise() {
  const host = document.querySelector(SIGN_UP_SELECTOR);
  if (!host) return;

  try {
    const clerk = await loadClerk();

    if (clerk.session && clerk.session.status === "active") {
      window.location.replace(AFTER_SIGN_UP_URL);
      return;
    }

    clerk.mountSignUp(host, {
      afterSignUpUrl: AFTER_SIGN_UP_URL,
      afterSignInUrl: AFTER_SIGN_UP_URL,
      signInUrl: SIGN_IN_URL,
    });
  } catch (error) {
    console.error("[signup] Unable to initialise Clerk", error);
    renderError(
      "We couldn't load the sign-up widget. Confirm your Clerk publishable key and try again."
    );
  }
}

initialise();
