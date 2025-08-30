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
  const bootstrapped = useRef(false);
  const { login } = useContext(AuthContext);

  const searchParams = new URLSearchParams(location.search);
  const isOrgSelectedManually = searchParams.get("selected") === "true";

useEffect(() => {
  if (!organization?.id || !isOrgSelectedManually || bootstrapped.current) return;

  bootstrapped.current = true;

  (async () => {
    const orgToken = await getToken();
    if (!orgToken) throw new Error("Missing org token");

    const username =
      user?.username ||
      user?.primaryEmailAddress?.emailAddress ||
      user?.id ||
      "clerk_user";

    // Step 1: Backend organization setup
    await createOrganisation(orgToken);

    // Step 2: Ensure user exists in Langflow backend
    const { justCreated } = await ensureLangflowUser(orgToken, username);

    // Step 3: Mark org as selected (store + session)
    authStore.getState().setIsOrgSelected(true);
    sessionStorage.setItem("isOrgSelected", "true");

    if (justCreated) {
      // Step 4a: If newly created, sign out and force login again
      await logout();
      navigate("/login", { replace: true });
    } else {
      // ✅ Step 4b: Log into backend using dummy password
      const tokens = await backendLogin(username, orgToken);

      // ✅ Step 5: Save Langflow tokens via AuthContext login
      login(orgToken, "login", tokens.refresh_token);

      // Step 6: Proceed to flows
      navigate("/flows", { replace: true });
    }
  })().catch((err) => {
    console.error("[OrgSwitcherPage] Bootstrap failed", err);
    bootstrapped.current = false;
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
