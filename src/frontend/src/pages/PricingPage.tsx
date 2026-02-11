import { useNavigate } from "react-router-dom";

export default function PricingPage() {
  const navigate = useNavigate();

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "grid",
        placeItems: "center",
        background: "linear-gradient(180deg, #0b1220 0%, #020617 100%)",
        color: "#e2e8f0",
        padding: "1.5rem",
      }}
    >
      <div
        style={{
          width: "100%",
          maxWidth: "720px",
          border: "1px solid rgba(148,163,184,.35)",
          borderRadius: "14px",
          background: "rgba(15, 23, 42, .75)",
          padding: "1.25rem",
        }}
      >
        <h1 style={{ marginTop: 0, fontSize: "1.75rem" }}>Pricing (Placeholder)</h1>
        <p style={{ opacity: 0.85, lineHeight: 1.6 }}>
          Your organization requires billing setup before entering flows. This is a temporary
          pricing page placeholder. Final Clerk + Paddle checkout UI will replace this soon.
        </p>

        <div style={{ display: "flex", gap: ".75rem", flexWrap: "wrap", marginTop: "1rem" }}>
          <button
            type="button"
            onClick={() => navigate("/organization")}
            style={{
              padding: ".65rem 1rem",
              borderRadius: "10px",
              border: "1px solid rgba(148,163,184,.45)",
              background: "rgba(30,41,59,.8)",
              color: "#e2e8f0",
              cursor: "pointer",
            }}
          >
            Back to organization
          </button>
          <button
            type="button"
            style={{
              padding: ".65rem 1rem",
              borderRadius: "10px",
              border: "1px solid rgba(56,189,248,.5)",
              background: "rgba(8,47,73,.8)",
              color: "#bae6fd",
              cursor: "not-allowed",
            }}
            disabled
          >
            Checkout coming soon
          </button>
        </div>
      </div>
    </div>
  );
}
