import { useMemo } from "react";

const plans = [
  {
    name: "Starter",
    description: "For individuals and early teams",
    price: "$19",
    seats: "1–3 seats",
  },
  {
    name: "Growth",
    description: "For growing organizations",
    price: "$49",
    seats: "4–15 seats",
  },
  {
    name: "Enterprise",
    description: "For advanced security and scale",
    price: "Custom",
    seats: "16+ seats",
  },
];

export default function PricingPage() {
  const subtitle = useMemo(
    () =>
      "Dummy pricing screen for Clerk/Paddle onboarding. Final checkout integration will be added next.",
    [],
  );

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "linear-gradient(180deg, #0f172a 0%, #020617 100%)",
        color: "#e2e8f0",
        padding: "2rem 1rem",
      }}
    >
      <div style={{ maxWidth: "980px", margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: "2rem" }}>
          <h1 style={{ fontSize: "2rem", fontWeight: 700, marginBottom: "0.75rem" }}>
            Pricing (Dummy UI)
          </h1>
          <p style={{ opacity: 0.8, maxWidth: "720px", margin: "0 auto" }}>{subtitle}</p>
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "1rem",
          }}
        >
          {plans.map((plan) => (
            <div
              key={plan.name}
              style={{
                backgroundColor: "rgba(15, 23, 42, 0.8)",
                border: "1px solid rgba(148, 163, 184, 0.35)",
                borderRadius: "0.875rem",
                padding: "1rem",
              }}
            >
              <h2 style={{ margin: 0, fontSize: "1.1rem" }}>{plan.name}</h2>
              <p style={{ opacity: 0.8, marginTop: "0.5rem", minHeight: "2.5rem" }}>{plan.description}</p>
              <div style={{ fontSize: "1.5rem", fontWeight: 700, marginTop: "0.25rem" }}>{plan.price}</div>
              <div style={{ opacity: 0.75, marginTop: "0.25rem" }}>{plan.seats}</div>
              <button
                type="button"
                style={{
                  marginTop: "0.9rem",
                  width: "100%",
                  padding: "0.6rem",
                  borderRadius: "0.6rem",
                  border: "1px solid rgba(148, 163, 184, 0.5)",
                  backgroundColor: "rgba(30, 41, 59, 0.7)",
                  color: "#e2e8f0",
                  cursor: "pointer",
                }}
              >
                Continue (coming soon)
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
