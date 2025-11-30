import { useEffect, useMemo, useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "@clerk/clerk-react";
import { useCookies } from "react-cookie";
import {
  hasWorkspaceSession,
  LANGFLOW_ACCESS_TOKEN,
  LANGFLOW_REFRESH_TOKEN,
} from "./session";

const API_BASE = (import.meta.env.VITE_LANGFLOW_API_BASE ?? "/api/v1/")
  .replace(/\/?$/, "/");

async function requestJson(path: string, token: string) {
  const response = await fetch(`${API_BASE}${path.replace(/^\/+/, "")}`, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
  });

  const text = await response.text();
  const data = text ? (JSON.parse(text) as Record<string, any>) : null;

  if (!response.ok) {
    const detail = (data?.detail as string) ?? response.statusText;
    throw new Error(detail || "Request failed");
  }

  return data;
}

type UserRecord = {
  id?: string;
  username?: string;
  full_name?: string;
  email?: string;
  is_superuser?: boolean;
  [key: string]: unknown;
};

export default function AdminSettingsPage() {
  const { isLoaded, isSignedIn } = useAuth();
  const navigate = useNavigate();
  const [cookies] = useCookies([LANGFLOW_ACCESS_TOKEN, LANGFLOW_REFRESH_TOKEN]);

  const [userRecord, setUserRecord] = useState<UserRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isLoaded) return;

    if (!isSignedIn) {
      navigate("/login", { replace: true });
      return;
    }

    if (!hasWorkspaceSession(cookies)) {
      navigate("/organization", { replace: true });
      return;
    }

    const token = cookies[LANGFLOW_ACCESS_TOKEN];
    if (!token) {
      setError("Missing access token.");
      setLoading(false);
      return;
    }

    requestJson("users/whoami", token)
      .then((data) => {
        setUserRecord(data);
        setLoading(false);
      })
      .catch((err: Error) => {
        setError(err.message);
        setLoading(false);
      });
  }, [cookies, isLoaded, isSignedIn, navigate]);

  const isSuperuser = useMemo(() => userRecord?.is_superuser === true, [userRecord]);

  if (!isLoaded) {
    return null;
  }

  if (!loading && userRecord && !isSuperuser) {
    return <Navigate to="/dashboard" replace />;
  }

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "#0b1021",
        color: "#e2e8f0",
        padding: "2rem",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <div
        style={{
          width: "min(900px, 100%)",
          background: "#0f172a",
          borderRadius: "1rem",
          border: "1px solid rgba(255,255,255,0.04)",
          boxShadow: "0 24px 80px rgba(0,0,0,0.35)",
          padding: "2rem",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginBottom: "1.5rem",
          }}
        >
          <div>
            <p style={{ margin: 0, color: "#94a3b8", fontSize: "0.9rem" }}>Admin</p>
            <h1 style={{ margin: 0, fontSize: "1.75rem", color: "#e2e8f0" }}>
              Admin Settings
            </h1>
            <p style={{ marginTop: "0.25rem", color: "#cbd5e1" }}>
              Review your user record as stored in Langflow.
            </p>
          </div>
          <div
            style={{
              padding: "0.35rem 0.75rem",
              borderRadius: "999px",
              background: isSuperuser ? "rgba(16, 185, 129, 0.15)" : "rgba(248, 113, 113, 0.1)",
              color: isSuperuser ? "#22c55e" : "#f87171",
              fontWeight: 600,
            }}
          >
            {isSuperuser ? "Superuser" : "Standard User"}
          </div>
        </div>

        {loading && (
          <div style={{ color: "#cbd5e1" }}>Loading user details…</div>
        )}

        {error && (
          <div
            style={{
              background: "rgba(248, 113, 113, 0.08)",
              border: "1px solid rgba(248, 113, 113, 0.3)",
              color: "#fecdd3",
              padding: "1rem",
              borderRadius: "0.75rem",
            }}
          >
            {error}
          </div>
        )}

        {!loading && !error && userRecord && (
          <div
            style={{
              marginTop: "1rem",
              display: "grid",
              gap: "0.75rem",
            }}
          >
            {Object.entries(userRecord).map(([key, value]) => (
              <div
                key={key}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  background: "rgba(255,255,255,0.02)",
                  border: "1px solid rgba(148, 163, 184, 0.15)",
                  borderRadius: "0.75rem",
                  padding: "0.85rem 1rem",
                }}
              >
                <div style={{ color: "#94a3b8", textTransform: "capitalize" }}>{key}</div>
                <div style={{ color: "#e2e8f0", fontWeight: 600 }}>
                  {typeof value === "boolean"
                    ? value.toString()
                    : value === null || value === undefined
                      ? "—"
                      : String(value)}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
