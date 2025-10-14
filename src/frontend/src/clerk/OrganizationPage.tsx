import { useLogout } from "@/clerk/auth";
import { AuthContext } from "@/contexts/authContext";
import { LoadingPage } from "@/pages/LoadingPage";
import authStore from "@/stores/authStore";
import {
  OrganizationList,
  useAuth,
  useOrganization,
  useUser,
} from "@clerk/clerk-react";
import { useContext, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  backendLogin,
  createOrganisation,
  ensureLangflowUser,
  setStoredActiveOrgId,
} from "./auth";

export default function OrganizationSwitcherPage() {
  const { getToken } = useAuth();
  const { organization } = useOrganization();
  const { user } = useUser();
  const navigate = useNavigate();
  const location = useLocation();
  const { mutateAsync: logout } = useLogout();
  const bootstrapped = useRef(false);
  const { login } = useContext(AuthContext);
  const justLoggedIn = useRef(false);
  const searchParams = new URLSearchParams(location.search);
  const isOrgSelectedManually = searchParams.get("selected") === "true";
  const [isBootstrapping, setIsBootstrapping] = useState(false);

  type EnterpriseDetectionUser = {
    enterpriseAccounts?: unknown[] | null;
    samlAccounts?: unknown[] | null;
    externalAccounts?:
      | Array<{
          provider?: string | null;
          strategy?: string | null;
          verification?: { strategy?: string | null } | null;
        }>
      | null;
  };
  const enterpriseDetectionUser = user as unknown as EnterpriseDetectionUser | null;
  const enterpriseAccounts = enterpriseDetectionUser?.enterpriseAccounts ?? [];
  const samlAccounts = enterpriseDetectionUser?.samlAccounts ?? [];
  const externalAccounts = enterpriseDetectionUser?.externalAccounts ?? [];
  const hasEnterpriseAccounts =
    (Array.isArray(enterpriseAccounts) && enterpriseAccounts.length > 0) ||
    (Array.isArray(samlAccounts) && samlAccounts.length > 0) ||
    (Array.isArray(externalAccounts) &&
      externalAccounts.some((account) => {
        if (!account) return false;
        const provider = account.provider?.toLowerCase() ?? "";
        const strategy = account.strategy?.toLowerCase() ?? "";
        const verificationStrategy = account.verification?.strategy?.toLowerCase() ?? "";
        return (
          strategy === "enterprise_sso" ||
          strategy === "saml" ||
          verificationStrategy === "enterprise_sso" ||
          verificationStrategy === "saml" ||
          provider === "saml" ||
          provider.startsWith("saml_")
        );
      }));
  const isEnterpriseUser = hasEnterpriseAccounts;
  const organizationMemberships = user?.organizationMemberships ?? [];
  const hasOrganizations = organizationMemberships.length > 0;
  const shouldShowEnterpriseEmptyState = isEnterpriseUser && !hasOrganizations;

  useEffect(() => {
    if (!organization?.id || !isOrgSelectedManually || bootstrapped.current)
      return;

    bootstrapped.current = true;
    setIsBootstrapping(true);
    const activeOrgId = organization.id;

    (async () => {
      console.log("[OrgSwitcherPage] Starting bootstrap flow...");

      const orgToken = await getToken();
      if (!orgToken) throw new Error("Missing Clerk org token");

      const username =
        user?.username ||
        user?.primaryEmailAddress?.emailAddress ||
        user?.id ||
        "clerk_user";
      try {
        // Step 1: Create backend organization (DB provisioning or linking)
        console.debug("[OrgSwitcherPage] Calling createOrganisation()");
        await createOrganisation(orgToken);
        console.debug("[OrgSwitcherPage] createOrganisation() completed");

        // Step 2: Ensure Langflow user exists via /whoami or /users
        console.debug("[OrgSwitcherPage] Calling ensureLangflowUser()");
        await ensureLangflowUser(orgToken, username);
        // Step 3: Backend login using dummy password flow
        console.debug("[OrgSwitcherPage] Calling backendLogin()");
        const tokens = await backendLogin(username, orgToken);
        console.debug("[OrgSwitcherPage] backendLogin() succeeded");

        // Step 4: Save access & refresh tokens into store and cookies
        login(orgToken, "login", tokens.refresh_token);
        justLoggedIn.current = true;

        // Step 5: Only now mark org as selected
        authStore.getState().setIsOrgSelected(true);
        sessionStorage.setItem("isOrgSelected", "true");
        setStoredActiveOrgId(activeOrgId);
        console.debug("[OrgSwitcherPage] Org selection state marked");

        // Step 6: Navigate to /flows
        console.debug("[OrgSwitcherPage] Redirecting to /flows");
        navigate("/flows", { replace: true });
      } catch (err) {
        if (!justLoggedIn.current) {
          console.error("[OrgSwitcherPage] Error during bootstrap", err);
          await logout();
        } else {
          console.warn(
            "[OrgSwitcherPage] Ignoring error after successful login",
            err,
          );
        }
      } finally {
        setIsBootstrapping(false);
      }
    })().catch((err) => {
      console.error("[OrgSwitcherPage] Bootstrap failed", err);
      bootstrapped.current = false;
      setIsBootstrapping(false);
    });
  }, [
    organization?.id,
    isOrgSelectedManually,
    getToken,
    user,
    navigate,
    login,
    logout,
  ]);

  if (isOrgSelectedManually || isBootstrapping) {
    return <LoadingPage />;
  }

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        padding: "2rem",
      }}
    >
      {shouldShowEnterpriseEmptyState ? (
        <div
          style={{
            maxWidth: "32rem",
            textAlign: "center",
            display: "flex",
            flexDirection: "column",
            gap: "0.75rem",
          }}
        >
          <h1 style={{ fontSize: "1.5rem", fontWeight: 600 }}>
            You&apos;re signed in with enterprise SSO
          </h1>
          <p style={{ color: "#4b5563", lineHeight: 1.5 }}>
            Your account is managed by your organization, so creating new
            organizations is disabled. Please contact your administrator if you
            need a new organization to be set up for you.
          </p>
        </div>
      ) : (
        <OrganizationList
          hidePersonal
          afterCreateOrganizationUrl="/organization?selected=true"
          afterSelectOrganizationUrl="/organization?selected=true"
          appearance={
            isEnterpriseUser
              ? {
                  elements: {
                    organizationListCreateOrganizationActionButton: {
                      display: "none",
                    },
                  },
                }
              : undefined
          }
        />
      )}
    </div>
  );
}
