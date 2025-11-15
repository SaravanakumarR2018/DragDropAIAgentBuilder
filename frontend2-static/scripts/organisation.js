import "./boot.js";
import { loadClerk } from "./clerk-loader.js";
import { createOrganisation, ensureLangflowUser, backendLogin } from "./auth-api.js";
import {
  clearOrganisationSelection,
  markOrganisationSelected,
  persistAuthSession,
} from "./storage-sync.js";
import { getStoredRedirectPath } from "./redirect-utils.js";

const ORG_LIST_SELECTOR = "#clerk-org-list";
const STATUS_MESSAGE_SELECTOR = ".org-status__message";
const DASHBOARD_URL = "/new/landingpage/dashboard";
const REDIRECT_QUERY = "selected";

function getStatusItem(step) {
  return document.querySelector(`.org-status__item[data-step="${step}"]`);
}

function setStatus(step, status, note = "") {
  const item = getStatusItem(step);
  if (!item) return;
  item.setAttribute("data-status", status);
  const noteEl = item.querySelector(".org-status__note");
  if (noteEl) {
    noteEl.textContent = note;
  }
}

function setStatusMessage(text, tone = "info") {
  const element = document.querySelector(STATUS_MESSAGE_SELECTOR);
  if (!element) return;
  element.textContent = text;
  element.dataset.tone = tone;
}

function deriveUsername(user) {
  if (!user) return "clerk_user";
  return (
    user.username ||
    user.primaryEmailAddress?.emailAddress ||
    user.emailAddresses?.[0]?.emailAddress ||
    [user.firstName, user.lastName].filter(Boolean).join(" ") ||
    user.id ||
    "clerk_user"
  );
}

function stripSelectedQuery() {
  const params = new URLSearchParams(window.location.search);
  params.delete(REDIRECT_QUERY);
  const next = params.toString();
  const newUrl = `${window.location.pathname}${next ? `?${next}` : ""}`;
  window.history.replaceState({}, "", newUrl);
}

async function bootstrapBackend(clerk) {
  let currentStep = "org";
  try {
    const session = clerk.session;
    if (!session) {
      throw new Error("Missing Clerk session. Please sign in again.");
    }

    const token = await session.getToken();
    if (!token) {
      throw new Error("Unable to fetch Clerk session token.");
    }

    const user = clerk.user;
    const username = deriveUsername(user);
    const activeOrgId =
      clerk.organization?.id ||
      clerk.user?.organizationMemberships?.find((membership) => membership?.organization?.id)?.organization?.id ||
      null;

    setStatus("org", "working", "Provisioning backend");
    await createOrganisation(token);
    setStatus("org", "success", "Organisation ready");

    currentStep = "user";
    setStatus("user", "working", "Checking user record");
    await ensureLangflowUser(token, username);
    setStatus("user", "success", "User confirmed");

    currentStep = "login";
    setStatus("login", "working", "Exchanging tokens");
    const tokens = await backendLogin(username, token);
    if (!tokens?.access_token) {
      throw new Error("Backend login did not return an access token.");
    }
    setStatus("login", "success", "Tokens issued");

    currentStep = "storage";
    setStatus("storage", "working", "Syncing browser stores");
    persistAuthSession({
      accessToken: tokens?.access_token,
      refreshToken: tokens?.refresh_token,
      autoLoginValue: "login",
    });
    markOrganisationSelected(activeOrgId);
    setStatus("storage", "success", "Ready");

    const redirectTarget = getStoredRedirectPath();
    if (redirectTarget) {
      setStatusMessage(
        `All set! Stored redirect: ${redirectTarget}. Redirecting to dashboard...`
      );
    } else {
      setStatusMessage("All set! Redirecting to dashboard...");
    }
    setTimeout(() => {
      window.location.replace(DASHBOARD_URL);
    }, 900);
  } catch (error) {
    console.error("[organisation] Bootstrap failed", error);
    setStatus(currentStep, "error", error.message || "Unexpected error");
    setStatusMessage(error.message || "Something went wrong", "error");
    clearOrganisationSelection();
  }
}

function mountOrganisationList(clerk) {
  const host = document.querySelector(ORG_LIST_SELECTOR);
  if (!host) return;
  clerk.mountOrganizationList(host, {
    afterSelectOrganizationUrl: `${DASHBOARD_URL.replace("/dashboard", "")}/organisation?selected=true`,
    afterCreateOrganizationUrl: `${DASHBOARD_URL.replace("/dashboard", "")}/organisation?selected=true`,
  });
}

async function initialise() {
  const params = new URLSearchParams(window.location.search);
  const shouldBootstrap = params.get(REDIRECT_QUERY) === "true";

  try {
    const clerk = await loadClerk();
    mountOrganisationList(clerk);

    if (shouldBootstrap) {
      clearOrganisationSelection();
      stripSelectedQuery();
      setStatusMessage("Syncing your Langflow session…");
      await bootstrapBackend(clerk);
    } else {
      const redirectTarget = getStoredRedirectPath();
      if (redirectTarget) {
        setStatusMessage(`After syncing you will be returned to ${redirectTarget}.`);
      } else {
        setStatusMessage("Select an organisation to continue.");
      }
    }
  } catch (error) {
    console.error("[organisation] Unable to load Clerk", error);
    setStatus("org", "error", "Clerk not available");
    setStatusMessage(
      "We couldn't load the organisation list. Check your Clerk configuration and reload.",
      "error"
    );
  }
}

initialise();

