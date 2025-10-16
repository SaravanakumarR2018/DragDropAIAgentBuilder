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
  const isEnterpriseUser = Boolean(
    user?.publicMetadata?.isEnterprise ||
      user?.publicMetadata?.plan === "enterprise" ||
      user?.unsafeMetadata?.isEnterprise ||
      user?.unsafeMetadata?.plan === "enterprise" ||
      user?.externalAccounts?.some((account) => {
        const provider = account.provider?.toLowerCase?.();
        return provider === "saml" || provider === "openid_connect";
      }) ||
      user?.externalAccounts?.some(
        (account) => account.verification?.strategy === "saml",
      ),
  );
  const organizationMemberships = user?.organizationMemberships ?? [];
  const shouldShowEnterpriseEmptyState =
    isEnterpriseUser && organizationMemberships.length === 0;
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
        border: "none",
        padding: 0,
        width: "100%",
      },
      card: {
        boxShadow: "none",
        border: "none",
      },
      organizationList: {
        width: "100%",
        marginTop: "0.375rem",
      },
      organizationList__title: {
        display: "none",
      },
      organizationList__subtitle: {
        display: "none",
      },
      organizationPreview: {
        borderRadius: "0.5rem",
        border: "1px solid #e5e7eb",
        padding: "0.75rem 1rem",
        marginBottom: "0.5rem",
      },
      organizationPreviewAvatarBox: {
        width: "2.5rem",
        height: "2.5rem",
      },
      organizationPreviewMainIdentifier: {
        fontWeight: 600,
        fontSize: "0.95rem",
      },
      organizationPreviewSecondaryIdentifier: {
        fontSize: "0.875rem",
        color: "#6b7280",
      },
      organizationSwitcherTrigger: {
        borderRadius: "0.5rem",
        border: "1px solid #e5e7eb",
        padding: "0.75rem 1rem",
      },
      organizationSwitcherTriggerIcon: {
        color: "#6366f1",
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
        background: "#f9fafb",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "32rem",
          background: "#ffffff",
          borderRadius: "1rem",
          boxShadow:
            "0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1)",
          padding: "2rem",
          display: "flex",
          flexDirection: "column",
          gap: "1.5rem",
        }}
      >
        {/* Brand Header - Gradient Style like Landing Page */}
        <div
          style={{
            alignSelf: "center",
            textAlign: "center",
            fontSize: "1.5rem",
            fontWeight: 700,
            background: "linear-gradient(135deg, #667eea 0%, #764ba2 100%)",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
            backgroundClip: "text",
            letterSpacing: "-0.02em",
          }}
        >
          Visual AI Agents Builder
        </div>

        {/* User Information Card */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.75rem",
            background: "#f9fafb",
            borderRadius: "0.5rem",
            padding: "0.75rem 1rem",
            border: "1px solid #e5e7eb",
          }}
        >
          {user?.imageUrl ? (
            <img
              src={user.imageUrl}
              alt={`${userDisplayName} avatar`}
              style={{
                width: "2.5rem",
                height: "2.5rem",
                borderRadius: "9999px",
                objectFit: "cover",
              }}
            />
          ) : (
            <div
              style={{
                width: "2.5rem",
                height: "2.5rem",
                borderRadius: "9999px",
                background: "#6366f1",
                color: "white",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontWeight: 600,
                fontSize: "0.875rem",
                textTransform: "uppercase",
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
            }}
          >
            <p
              style={{
                margin: 0,
                fontSize: "0.95rem",
                fontWeight: 500,
                color: "#111827",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              title={primaryEmailAddress || ""}
            >
              {primaryEmailAddress}
            </p>
            <p
              style={{
                margin: 0,
                fontSize: "0.875rem",
                color: "#6b7280",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              title={primaryEmailAddress || ""}
            >
              {primaryEmailAddress}
            </p>
          </div>
        </div>

        {/* Header - with reduced gap below */}
        <div
          style={{
            textAlign: "center",
            fontSize: "1.125rem",
            fontWeight: 600,
            color: "#111827",
            marginBottom: "-1.125rem",
          }}
        >
          Choose an organization
        </div>

        {/* Organization List - Clerk Component (styled to blend in) */}
        {shouldShowEnterpriseEmptyState ? (
          <div
            style={{
              textAlign: "center",
              display: "flex",
              flexDirection: "column",
              gap: "0.75rem",
              padding: "1rem 0.5rem",
            }}
          >
            <p
              style={{
                fontSize: "1.125rem",
                fontWeight: 600,
                color: "#111827",
                margin: 0,
                lineHeight: 1.4,
              }}
            >
              No active organization
            </p>
            <p
              style={{
                fontSize: "0.9375rem",
                color: "#6b7280",
                lineHeight: 1.6,
                margin: 0,
                maxWidth: "28rem",
                marginLeft: "auto",
                marginRight: "auto",
              }}
            >
              You don&apos;t have an active organization assigned to your
              account. Please contact your administrator to get access.
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
