import { useAuth } from "@clerk/clerk-react";
import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";

const API_BASE = (import.meta.env.VITE_LANGFLOW_API_BASE ?? "/api/v1/").replace(/\/?$/, "/");

function apiUrl(path: string) {
  return `${API_BASE}${path.replace(/^\/+/, "")}`;
}

export default function AdminDetails() {
  const { isLoaded, isSignedIn, getToken } = useAuth();
  const [loading, setLoading] = useState(true);
  const [whoami, setWhoami] = useState<Record<string, any> | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    (async () => {
      if (!isLoaded || !isSignedIn) return;
      try {
        const token = await getToken();
        const res = await fetch(apiUrl("users/whoami"), {
          headers: {
            Accept: "application/json",
            Authorization: token ? `Bearer ${token}` : "",
          },
        });
        if (!res.ok) {
          const txt = await res.text();
          throw new Error(txt || res.statusText);
        }
        const data = (await res.json()) as Record<string, any>;
        if (mounted) setWhoami(data);
      } catch (err: any) {
        if (mounted) setError(err?.message ?? String(err));
      } finally {
        if (mounted) setLoading(false);
      }
    })();

    return () => {
      mounted = false;
    };
  }, [getToken, isLoaded, isSignedIn]);

  // Not loaded yet - show nothing (Clerk will mount)
  if (!isLoaded) return null;

  // If not signed in, send to login
  if (!isSignedIn) return <Navigate to="/login" replace />;

  // Still loading whoami
  if (loading) {
    return (
      <div style={{ padding: "2rem", textAlign: "center" }}>
        <div>Loading admin details…</div>
      </div>
    );
  }

  // If we failed to fetch whoami, show an error
  if (error) {
    return (
      <div style={{ padding: "2rem", maxWidth: 720, margin: "0 auto" }}>
        <h2>Unable to load admin details</h2>
        <pre style={{ whiteSpace: "pre-wrap" }}>{error}</pre>
      </div>
    );
  }

  // If not a superuser, redirect to dashboard inside the landing app
  if (!whoami?.is_superuser && !whoami?.is_super) {
    return <Navigate to="/dashboard" replace />;
  }

  // Render admin details
  return (
    <div style={{ padding: "2rem", maxWidth: 900, margin: "0 auto" }}>
      <h1>Admin details</h1>
      <p>This page is accessible only to superusers.</p>

      <section style={{ marginTop: "1rem", background: "#0f172a", color: "#e6eef8", padding: "1rem", borderRadius: 8 }}>
        <h3 style={{ color: "#93c5fd", margin: 0, marginBottom: 8 }}>User summary</h3>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: "0.5rem", alignItems: "center" }}>
          <div><strong>Username</strong></div>
          <div style={{ color: "#e6eef8" }}>{whoami?.username ?? whoami?.email ?? whoami?.id}</div>

          <div><strong>Email</strong></div>
          <div style={{ color: "#e6eef8" }}>{whoami?.email ?? whoami?.primary_email ?? "-"}</div>

          <div><strong>Superuser</strong></div>
          <div style={{ color: "#e6eef8" }}>{String(Boolean(whoami?.is_superuser || whoami?.is_super))}</div>
        </div>
      </section>

      <section style={{ marginTop: "1rem" }}>
        <h3>Full response</h3>
        <pre style={{ whiteSpace: "pre-wrap", background: "#0f172a", color: "#e6eef8", padding: "1rem", borderRadius: 8 }}>{JSON.stringify(whoami, null, 2)}</pre>
      </section>
    </div>
  );
}
