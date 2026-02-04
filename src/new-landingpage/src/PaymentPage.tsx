import {
  SignedIn,
  SignedOut,
  useAuth,
  useOrganization,
  useUser,
} from "@clerk/clerk-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Navigate } from "react-router-dom";
import { useCookies } from "react-cookie";
import logoicon from "./new-assets/visualailogo.png";
import ProgressBar from "./ProgressBar";
import {
  ACTIVE_ORG_STORAGE_KEY,
  LANGFLOW_ACCESS_TOKEN,
  LANGFLOW_AUTO_LOGIN_OPTION,
  LANGFLOW_REFRESH_TOKEN,
  ORG_SELECTED_KEY,
} from "./session";
import { requestJson } from "./apiClient";

const PLANS = [
  {
    key: "starter_pack_monthly",
    name: "Starter",
    description: "For early stage teams experimenting with AI workflows.",
  },
  {
    key: "pro_pack_monthly",
    name: "Pro",
    description: "For growing teams scaling production-grade automations.",
  },
] as const;

type PlanKey = (typeof PLANS)[number]["key"];

export default function PaymentPage() {
  const { isLoaded, isSignedIn, getToken } = useAuth();
  const { organization } = useOrganization();
  const { user } = useUser();
  const [, setCookie, removeCookie] = useCookies([
    LANGFLOW_ACCESS_TOKEN,
    LANGFLOW_REFRESH_TOKEN,
    LANGFLOW_AUTO_LOGIN_OPTION,
  ]);

  const [planKey, setPlanKey] = useState<PlanKey>("starter_pack_monthly");
  const [seats, setSeats] = useState(1);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const displayName =
    user?.fullName ||
    user?.username ||
    user?.primaryEmailAddress?.emailAddress ||
    "Current member";

  const emailAddress =
    user?.primaryEmailAddress?.emailAddress ||
    user?.emailAddresses?.[0]?.emailAddress ||
    "";

  const avatarUrl = user?.imageUrl;
  const initials = displayName
    .split(" ")
    .map((segment) => segment[0])
    .join("")
    .slice(0, 2)
    .toUpperCase();

  const activeOrgId = organization?.id ?? null;

  const persistSession = useCallback(
    (accessToken: string, refreshToken: string | null, orgId: string) => {
      const cookieOptions = { path: "/", sameSite: "lax" as const };

      setCookie(LANGFLOW_ACCESS_TOKEN, accessToken, cookieOptions);
      setCookie(LANGFLOW_AUTO_LOGIN_OPTION, "login", cookieOptions);

      if (refreshToken) {
        setCookie(LANGFLOW_REFRESH_TOKEN, refreshToken, cookieOptions);
      }

      localStorage.setItem(ORG_SELECTED_KEY, "true");
      localStorage.setItem(ACTIVE_ORG_STORAGE_KEY, orgId);
    },
    [setCookie],
  );

  const clearSession = useCallback(() => {
    removeCookie(LANGFLOW_ACCESS_TOKEN, { path: "/" });
    removeCookie(LANGFLOW_REFRESH_TOKEN, { path: "/" });
    removeCookie(LANGFLOW_AUTO_LOGIN_OPTION, { path: "/" });
    localStorage.removeItem(ORG_SELECTED_KEY);
    localStorage.removeItem(ACTIVE_ORG_STORAGE_KEY);
  }, [removeCookie]);

  const goToFlows = useCallback(() => {
    window.location.assign("/flows");
  }, []);

  const goToOrgSelection = useCallback(() => {
    window.location.assign("/organization");
  }, []);

  const selectedPlan = useMemo(
    () => PLANS.find((plan) => plan.key === planKey),
    [planKey],
  );

  const handleSeatChange = (value: number) => {
    if (Number.isNaN(value) || value < 1) {
      setSeats(1);
      return;
    }
    setSeats(value);
  };

  const checkSubscriptionStatus = useCallback(
    async (token: string) => {
      return requestJson("billing/subscription-status", {
        method: "GET",
        token,
      });
    },
  );

  useEffect(() => {
    if (!isLoaded || !isSignedIn) return;
    if (!activeOrgId) return;

    (async () => {
      try {
        const token = await getToken({ skipCache: true });
        if (!token) return;
        const statusResponse = await checkSubscriptionStatus(token);
        if (statusResponse?.has_access) {
          goToFlows();
        }
      } catch (err) {
        console.warn("[PaymentPage] Unable to check existing subscription", err);
      }
    })();
  }, [activeOrgId, checkSubscriptionStatus, getToken, goToFlows, isLoaded, isSignedIn]);

  const handleSubmit = useCallback(async () => {
    if (!activeOrgId) {
      setError("No organization selected.");
      return;
    }

    setError(null);
    setStatus("Preparing checkout...");
    setIsSubmitting(true);

    try {
      const token = await getToken();
      if (!token) {
        throw new Error("Unable to retrieve Clerk token.");
      }

      await requestJson("billing/create-subscription", {
        method: "POST",
        token,
        body: JSON.stringify({ plan_key: planKey, quantity: seats }),
      });

      setStatus("Finalizing access...");
      const refreshedToken = await getToken({ skipCache: true });
      const loginToken = refreshedToken ?? token;

      const username =
        user?.username ||
        user?.primaryEmailAddress?.emailAddress ||
        user?.id ||
        "clerk_user";

      const tokens = await requestJson("login", {
        method: "POST",
        token: loginToken,
        body: new URLSearchParams({
          username,
          password: "clerk_dummy_password",
        }),
      });

      persistSession(loginToken, (tokens as any)?.refresh_token ?? null, activeOrgId);
      setStatus("Redirecting to workspace...");
      goToFlows();
    } catch (err: any) {
      console.error("[PaymentPage] Payment flow failed", err);
      const message = err instanceof Error ? err.message : "Payment failed";
      setError(message);
      setStatus(null);
      clearSession();
    } finally {
      setIsSubmitting(false);
    }
  }, [activeOrgId, clearSession, getToken, goToFlows, persistSession, planKey, seats, user]);

  if (!isLoaded) {
    return null;
  }

  if (!isSignedIn) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div
      style={{
        display: "grid",
        placeItems: "center",
        minHeight: "100vh",
        padding: "2rem 1.25rem",
        backgroundColor: "#f8fafc",
        boxSizing: "border-box",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "560px",
          display: "flex",
          flexDirection: "column",
          gap: "1.5rem",
          alignItems: "center",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "0.75rem",
          }}
        >
          <img
            src={logoicon}
            alt="Visual AI Agent Builder Logo"
            style={{
              width: "40px",
              height: "40px",
              objectFit: "contain",
              borderRadius: "8px",
            }}
          />
          <span
            style={{
              background: "linear-gradient(90deg, #4f46e5 0%, #38bdf8 80%)",
              WebkitBackgroundClip: "text",
              color: "transparent",
              fontSize: "1.125rem",
              fontWeight: 700,
              letterSpacing: "0.01em",
            }}
          >
            Visual AI Agents Builder
          </span>
        </div>

        <div
          style={{
            alignItems: "center",
            backgroundColor: "#ffffff",
            border: "1px solid rgba(15, 23, 42, 0.08)",
            borderRadius: "1rem",
            boxShadow: "0 8px 28px rgba(15, 23, 42, 0.06)",
            display: "flex",
            gap: "0.75rem",
            padding: "0.875rem 1.25rem",
            width: "100%",
          }}
        >
          <div
            style={{
              width: "2.75rem",
              height: "2.75rem",
              borderRadius: "9999px",
              overflow: "hidden",
              border: "2px solid rgba(99, 102, 241, 0.35)",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              background:
                "linear-gradient(135deg, rgba(99,102,241,0.16), rgba(129,140,248,0.22))",
            }}
          >
            {avatarUrl ? (
              <img
                src={avatarUrl}
                alt={displayName}
                style={{ width: "100%", height: "100%", objectFit: "cover" }}
              />
            ) : (
              <span
                style={{
                  color: "#312e81",
                  fontSize: "1.5rem",
                  fontWeight: 600,
                }}
              >
                {initials}
              </span>
            )}
          </div>
          <div style={{ display: "flex", flex: 1, flexDirection: "column" }}>
            <div style={{ fontSize: "1rem", fontWeight: 600, color: "#1e293b" }}>
              {displayName}
            </div>
            <div style={{ color: "#475569", fontSize: "0.9rem" }}>
              {emailAddress || "Signed in user"}
            </div>
          </div>
        </div>

        <div
          style={{
            width: "100%",
            backgroundColor: "#ffffff",
            borderRadius: "1rem",
            border: "1px solid rgba(15, 23, 42, 0.08)",
            boxShadow: "0 10px 30px rgba(15, 23, 42, 0.08)",
            padding: "1.5rem",
            display: "flex",
            flexDirection: "column",
            gap: "1.25rem",
          }}
        >
          <div>
            <h2 style={{ fontSize: "1.25rem", fontWeight: 700, marginBottom: "0.25rem" }}>
              Choose your plan
            </h2>
            <p style={{ color: "#475569", fontSize: "0.95rem" }}>
              Select a plan and confirm how many seats you need for your organization.
            </p>
          </div>

          <div style={{ display: "grid", gap: "0.75rem" }}>
            {PLANS.map((plan) => (
              <label
                key={plan.key}
                style={{
                  display: "flex",
                  alignItems: "flex-start",
                  gap: "0.75rem",
                  padding: "0.75rem 1rem",
                  borderRadius: "0.75rem",
                  border:
                    plan.key === planKey
                      ? "1px solid #6366f1"
                      : "1px solid rgba(148, 163, 184, 0.6)",
                  backgroundColor:
                    plan.key === planKey ? "#eef2ff" : "transparent",
                  cursor: "pointer",
                }}
              >
                <input
                  type="radio"
                  name="plan"
                  value={plan.key}
                  checked={plan.key === planKey}
                  onChange={() => setPlanKey(plan.key)}
                  style={{ marginTop: "0.2rem" }}
                />
                <div>
                  <div style={{ fontWeight: 600, color: "#1e293b" }}>{plan.name}</div>
                  <div style={{ color: "#64748b", fontSize: "0.9rem" }}>
                    {plan.description}
                  </div>
                </div>
              </label>
            ))}
          </div>

          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: "0.5rem",
            }}
          >
            <label style={{ fontWeight: 600, color: "#1e293b" }}>
              Seats for your organization
            </label>
            <input
              type="number"
              min={1}
              value={seats}
              onChange={(event) => handleSeatChange(Number(event.target.value))}
              style={{
                padding: "0.75rem 0.85rem",
                borderRadius: "0.75rem",
                border: "1px solid rgba(148, 163, 184, 0.6)",
                fontSize: "1rem",
              }}
            />
            <div style={{ color: "#64748b", fontSize: "0.85rem" }}>
              You can update seats later. Current selection: {seats} seat
              {seats === 1 ? "" : "s"}.
            </div>
          </div>

          {selectedPlan && (
            <div
              style={{
                padding: "0.75rem 1rem",
                borderRadius: "0.75rem",
                backgroundColor: "#f8fafc",
                border: "1px solid rgba(148, 163, 184, 0.5)",
                color: "#1e293b",
                fontSize: "0.9rem",
              }}
            >
              Selected plan: <strong>{selectedPlan.name}</strong>
            </div>
          )}

          {error && (
            <div
              style={{
                padding: "0.75rem 1rem",
                borderRadius: "0.75rem",
                backgroundColor: "#fef2f2",
                border: "1px solid #fecaca",
                color: "#b91c1c",
                fontSize: "0.875rem",
              }}
            >
              {error}
            </div>
          )}

          {status && (
            <div
              style={{
                padding: "0.5rem 0.75rem",
                borderRadius: "999px",
                backgroundColor: "#eff6ff",
                color: "#1d4ed8",
                fontSize: "0.875rem",
                textAlign: "center",
              }}
            >
              {status}
            </div>
          )}

          <button
            type="button"
            onClick={handleSubmit}
            disabled={isSubmitting}
            style={{
              padding: "0.85rem 1rem",
              borderRadius: "0.85rem",
              backgroundColor: isSubmitting ? "#c7d2fe" : "#4f46e5",
              color: "#ffffff",
              border: "none",
              fontWeight: 600,
              cursor: isSubmitting ? "not-allowed" : "pointer",
            }}
          >
            {isSubmitting ? "Processing..." : "Continue to payment"}
          </button>

          {isSubmitting && (
            <div style={{ display: "flex", justifyContent: "center" }}>
              <ProgressBar remSize={16} />
            </div>
          )}
        </div>

        <SignedOut>
          <div
            style={{
              width: "100%",
              padding: "0.75rem 1rem",
              borderRadius: "0.75rem",
              backgroundColor: "#eff6ff",
              border: "1px solid #bfdbfe",
              color: "#1d4ed8",
              fontSize: "0.875rem",
              textAlign: "center",
            }}
          >
            Your session expired. Please log in again.
          </div>
        </SignedOut>

        <SignedIn>
          {!activeOrgId && (
            <button
              type="button"
              onClick={goToOrgSelection}
              style={{
                padding: "0.65rem 1rem",
                borderRadius: "999px",
                border: "1px solid rgba(99, 102, 241, 0.4)",
                backgroundColor: "transparent",
                color: "#4338ca",
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Select an organization
            </button>
          )}
        </SignedIn>
      </div>
    </div>
  );
}
