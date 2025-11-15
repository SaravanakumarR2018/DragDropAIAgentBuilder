import "./boot.js";
import { loadClerk } from "./clerk-loader.js";
import { clearAuthSession, getAuthSnapshot } from "./storage-sync.js";
import { getStoredRedirectPath } from "./redirect-utils.js";

const ORG_SELECTOR = "#dashboard-org";
const REDIRECT_SELECTOR = "#dashboard-redirect";
const LOGOUT_SELECTOR = "#dashboard-logout";
const LOGIN_URL = "/new/landingpage/login";
const ORG_URL = "/new/landingpage/organisation";

function redirect(url) {
  window.location.replace(url);
}

function populateRedirect() {
  const redirectTarget = getStoredRedirectPath();
  const redirectElement = document.querySelector(REDIRECT_SELECTOR);
  if (!redirectElement) return;
  redirectElement.textContent = redirectTarget || "None stored";
}

async function populateOrganisationDetails() {
  const orgElement = document.querySelector(ORG_SELECTOR);
  if (!orgElement) return;

  const { activeOrgId } = getAuthSnapshot();
  let label = activeOrgId || "Not set";

  try {
    const clerk = await loadClerk();
    const organisation = clerk.organization;
    if (organisation) {
      label = organisation.name ? `${organisation.name} (${organisation.id})` : organisation.id;
    }
  } catch (error) {
    console.warn("[dashboard] Unable to load Clerk organisation", error);
  }

  orgElement.textContent = label;
}

async function handleLogout() {
  clearAuthSession();
  try {
    const clerk = await loadClerk();
    await clerk.signOut();
  } catch (error) {
    console.warn("[dashboard] Clerk sign out failed", error);
  }
  redirect(LOGIN_URL);
}

function ensureAccess() {
  const snapshot = getAuthSnapshot();
  if (!snapshot.accessToken) {
    redirect(LOGIN_URL);
    return false;
  }
  if (!snapshot.isOrgSelected) {
    redirect(ORG_URL);
    return false;
  }
  return true;
}

async function initialise() {
  if (!ensureAccess()) return;
  populateRedirect();
  populateOrganisationDetails();
  const logoutButton = document.querySelector(LOGOUT_SELECTOR);
  if (logoutButton) {
    logoutButton.addEventListener("click", () => {
      handleLogout();
    });
  }
}

initialise();
