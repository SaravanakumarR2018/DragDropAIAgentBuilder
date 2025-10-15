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

  const primaryEmailAddress =
    user?.primaryEmailAddress?.emailAddress ||
    user?.emailAddresses?.[0]?.emailAddress ||
    null;
  const userDisplayName =
    user?.fullName || user?.username || primaryEmailAddress || "Signed in user";
  const userInitials =
    userDisplayName
      .split(/\s+/)
      .filter(Boolean)
      .map((chunk) => chunk.charAt(0).toUpperCase())
      .join("") ||
    (primaryEmailAddress ? primaryEmailAddress.charAt(0).toUpperCase() : "?");

  const baseAppearance = {
    elements: {
      rootBox: {
        boxShadow: "none",
        backgroundColor: "transparent",
        padding: 0,
        width: "100%",
      },
      organizationList: {
        width: "100%",
        gap: "1rem",
      },
      organizationList__title: {
        display: "none",
      },
      organizationList__subtitle: {
        display: "none",
      },
      organizationSwitcherTrigger: {
        borderRadius: "0.75rem",
        border: "1px solid #e5e7eb",
        boxShadow: "none",
      },
      organizationSwitcherTriggerIcon: {
        color: "#6366f1",
      },
      organizationSwitcherTriggerText: {
        fontWeight: 600,
      },
      organizationSwitcherTriggerSubtitle: {
        color: "#4b5563",
      },
    },
  };

  const organizationListAppearance = isEnterpriseUser
    ? {
        ...baseAppearance,
        elements: {
          ...baseAppearance.elements,
          organizationListCreateOrganizationActionButton: {
            display: "none",
          },
        },
      }
    : baseAppearance;

  return (
    <div
      style={{
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        minHeight: "100vh",
        padding: "2rem",
        backgroundColor: "#f5f7fb",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "28rem",
          background: "#ffffff",
          borderRadius: "1.5rem",
          boxShadow: "0 18px 40px rgba(15, 23, 42, 0.12)",
          border: "1px solid rgba(148, 163, 184, 0.18)",
          padding: "2.25rem 2rem",
          display: "flex",
          flexDirection: "column",
          gap: "1.5rem",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "1rem",
            background: "#f4f5ff",
            borderRadius: "0.9rem",
            padding: "0.9rem 1.1rem",
            border: "1px solid rgba(99, 102, 241, 0.18)",
          }}
        >
          {user?.imageUrl ? (
            <img
              src={user.imageUrl}
              alt={`${userDisplayName} avatar`}
              style={{
                width: "3rem",
                height: "3rem",
                borderRadius: "9999px",
                objectFit: "cover",
                border: "2px solid rgba(99, 102, 241, 0.35)",
              }}
            />
          ) : (
            <div
              style={{
                width: "3rem",
                height: "3rem",
                borderRadius: "9999px",
                background: "#6366f1",
                color: "white",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 600,
                fontSize: "1.125rem",
                textTransform: "uppercase",
                lineHeight: 1,
              }}
            >
              {userInitials.slice(0, 2)}
            </div>
          )}
          <div
            style={{
              flex: 1,
              minWidth: 0,
              display: "flex",
              flexDirection: "column",
              gap: "0.2rem",
            }}
          >
            <p
              style={{
                margin: 0,
                fontSize: "1rem",
                fontWeight: 600,
                color: "#1f2937",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              title={userDisplayName}
            >
              {userDisplayName}
            </p>
            {primaryEmailAddress && (
              <p
                style={{
                  margin: 0,
                  fontSize: "0.875rem",
                  color: "#4b5563",
                  overflowWrap: "anywhere",
                }}
                title={primaryEmailAddress}
              >
                {primaryEmailAddress}
              </p>
            )}
          </div>
        </div>

        <div style={{ textAlign: "center" }}>
          <h1
            style={{
              margin: 0,
              fontSize: "1.35rem",
              fontWeight: 600,
              color: "#111827",
            }}
          >
            Choose an organization
          </h1>
          <p
            style={{
              margin: "0.45rem 0 0",
              fontSize: "0.95rem",
              color: "#4b5563",
            }}
          >
            to continue to Visual AI Agents Builder
          </p>
        </div>

        {shouldShowEnterpriseEmptyState ? (
          <div
            style={{
              textAlign: "center",
              display: "flex",
              flexDirection: "column",
              gap: "0.75rem",
              color: "#4b5563",
            }}
          >
            <h2 style={{ fontSize: "1.25rem", fontWeight: 600, margin: 0 }}>
              You&apos;re signed in with enterprise SSO
            </h2>
            <p style={{ lineHeight: 1.5, margin: 0 }}>
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
            appearance={organizationListAppearance}
          />
        )}
      </div>
    </div>
  );
}
