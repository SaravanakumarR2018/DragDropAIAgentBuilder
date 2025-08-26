import { OrganizationList, useAuth, useOrganization, useUser } from "@clerk/clerk-react";
import { useContext, useEffect, useRef } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ensureLangflowUser, createOrganisation, backendLogin } from "./auth";
import authStore from "@/stores/authStore";
import { useLogout } from "@/clerk/auth";
import { AuthContext } from "@/contexts/authContext";

export default function OrganizationSwitcherPage() {
  const { getToken } = useAuth();
  const { organization } = useOrganization();
  const { user } = useUser();
  const navigate = useNavigate();
  const location = useLocation();
  const { mutateAsync: logout } = useLogout();
  const bootstrappedSession = useRef<string | null>(null);
  const { login } = useContext(AuthContext);

  const searchParams = new URLSearchParams(location.search);
  const isOrgSelectedManually = searchParams.get("selected") === "true";

  useEffect(() => {
    // Skip bootstrap if:
    //  - No org selected
    //  - Already bootstrapped for this session
    if (!organization?.id || !isOrgSelectedManually) return;

    const bootstrapKey = organization?.id + (user?.id || "");
    if (bootstrappedSession.current === bootstrapKey) {
      console.debug("[OrgSwitcherPage] Skipping bootstrap (already processed for this session)");
      return;
    }

    bootstrappedSession.current = bootstrapKey;

    (async () => {
      const orgToken = await getToken();
      if (!orgToken) throw new Error("Missing org token");

      const username =
        user?.username ||
        user?.primaryEmailAddress?.emailAddress ||
        user?.id ||
        "clerk_user";

      console.log("[OrgSwitcherPage] Bootstrapping for user:", username);

      // Step 1: Create backend org if needed
      await createOrganisation(orgToken);

      // Step 2: Ensure Langflow user exists
      const { justCreated } = await ensureLangflowUser(orgToken, username);

      // Step 3: Mark org as selected
      authStore.getState().setIsOrgSelected(true);
      sessionStorage.setItem("isOrgSelected", "true");

      if (justCreated) {
        // Newly created user: force login again to issue fresh backend tokens
        console.log("[OrgSwitcherPage] Langflow user created → forcing re-login");
        await logout();
        navigate("/login", { replace: true });
      } else {
        // Step 4: Log into Langflow backend
        const tokens = await backendLogin(username, orgToken);

        // Step 5: Save Langflow tokens in AuthContext
        login(orgToken, "login", tokens.refresh_token);

        // Step 6: Navigate to flows
        console.log("[OrgSwitcherPage] Bootstrap complete → navigating to /flows");
        navigate("/flows", { replace: true });
      }
    })().catch((err) => {
      console.error("[OrgSwitcherPage] Bootstrap failed", err);
      bootstrappedSession.current = null;
    });
  }, [organization?.id, isOrgSelectedManually, getToken, user, navigate]);

  return (
    <div style={{ display: "flex", justifyContent: "center", alignItems: "center", minHeight: "100vh" }}>
      <OrganizationList
        hidePersonal
        afterCreateOrganizationUrl="/organization?selected=true"
        afterSelectOrganizationUrl="/organization?selected=true"
      />
    </div>
  );
}
