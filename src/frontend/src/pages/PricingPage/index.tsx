import type { SVGProps } from "react";
import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {useAuth} from "@clerk/clerk-react";
import axios from "axios";
import { getURL } from "../../controllers/API/helpers/constants";

const MIN_SEATS = 1;

type PlanKey = "starter" | "pro" | "enterprise";

const PLAN_KEY_MAP: Record<PlanKey, "starter_pack_monthly" | "pro_pack_monthly" | "enterprise_pack_monthly"> = {
  starter: "starter_pack_monthly",
  pro: "pro_pack_monthly",
  enterprise: "enterprise_pack_monthly",
};

interface PlanConfig {
  key: PlanKey;
  name: string;
  pricePerSeat: number;
  hasTrial: boolean;
  trialDays?: number;
  features: string[];
}

const PLANS: PlanConfig[] = [
  {
    key: "starter",
    name: "Starter Pack",
    pricePerSeat: 20,
    hasTrial: true,
    trialDays: 7,
    features: [
      "Shared database",
      "Standard rate limits",
      "Core visual builder features",
      "Community support",
    ],
  },
  {
    key: "pro",
    name: "Pro Pack",
    pricePerSeat: 50,
    hasTrial: false,
    features: [
      "Separate database",
      "Highly enabled rate limits",
      "Team collaboration tools",
      "Priority email support",
    ],
  },
  {
    key: "enterprise",
    name: "Enterprise Pack",
    pricePerSeat: 120,
    hasTrial: false,
    features: [
      "Dedicated environments",
      "Custom security & compliance",
      "SSO and role-based access",
      "Premium SLA & support",
    ],
  },
];

function CheckIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" {...props}>
      <path
        d="M20.285 6.709a1 1 0 0 1 0 1.414l-9.192 9.192a1 1 0 0 1-1.414 0L3.715 11.55a1 1 0 0 1 1.414-1.415l5.136 5.136 8.485-8.485a1 1 0 0 1 1.535-.077z"
        fill="currentColor"
      />
    </svg>
  );
}

export default function PricingPage() {
  const navigate = useNavigate();
  const { getToken } = useAuth();

  const [selectedPlan, setSelectedPlan] = useState<PlanKey>("starter");
  const [seatsByPlan, setSeatsByPlan] = useState<Record<PlanKey, number>>({
    starter: 1,
    pro: 1,
    enterprise: 5,
  });

  const handleDecrement = (planKey: PlanKey) => {
    setSeatsByPlan((prev) => ({
      ...prev,
      [planKey]: Math.max(MIN_SEATS, prev[planKey] - 1),
    }));
  };

  const handleIncrement = (planKey: PlanKey) => {
    setSeatsByPlan((prev) => ({
      ...prev,
      [planKey]: prev[planKey] + 1,
    }));
  };

  const handleSelectPlan = async (plan: PlanConfig) => {
    const token = await getToken();
    const seats = seatsByPlan[plan.key];

    setSelectedPlan(plan.key);

    const payload = {
      plan_key: PLAN_KEY_MAP[plan.key],
      seats,
    };

    try {
      const response = await axios.post(
        getURL("CREATE_SUBSCRIPTION"),
        payload,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );

      console.log("Subscription created successfully:", response.data);
      // Handle successful subscription creation
      // e.g., redirect to success page or show confirmation
    } catch (error) {
      console.error("Failed to create subscription:", error);
      // Handle error - show error message to user
    }
  };

  return (
    <div className="min-h-screen bg-[#0f1217] px-4 py-14 text-white">
      <div className="mx-auto max-w-7xl">
        <div className="rounded-2xl border border-white/10 bg-[#0f1217] p-8">
          <div className="text-center">
            <h1 className="text-2xl font-semibold">
              Simple, Scalable Pricing
            </h1>
            <p className="mt-3 text-white/70">
              Choose the plan that matches your team size and scale with
              confidence.
            </p>
          </div>

          <div className="mt-10 grid gap-6 md:grid-cols-3">
            {PLANS.map((plan) => {
              const seats = seatsByPlan[plan.key];
              const total = useMemo(
                () => seats * plan.pricePerSeat,
                [seats, plan.pricePerSeat],
              );

              return (
                <div
                  key={plan.key}
                  className={`flex h-full flex-col rounded-xl border p-6 ${
                    selectedPlan === plan.key
                      ? "border-cyan-400/50 bg-[#11161d]"
                      : "border-white/10 bg-[#0f1217]"
                  }`}
                >
                  <div className="text-sm text-white/60">{plan.name}</div>
                  <div className="mt-2 text-3xl font-semibold">
                    ${plan.pricePerSeat}/seat/month
                  </div>

                  {plan.hasTrial && (
                    <div className="mt-1 text-sm text-cyan-300">
                      {plan.trialDays}-day free trial
                    </div>
                  )}

                  <div className="mt-5 rounded-lg border border-white/10 bg-black/20 p-4">
                    <div className="text-xs uppercase tracking-wide text-white/60">
                      Seats
                    </div>

                    <div className="mt-2 flex items-center gap-3">
                      <button
                        type="button"
                        onClick={() => handleDecrement(plan.key)}
                        className="h-8 w-8 rounded-md border border-white/20 text-lg leading-none text-white hover:bg-white/10"
                      >
                        -
                      </button>

                      <span className="min-w-8 text-center text-xl font-semibold">
                        {seats}
                      </span>

                      <button
                        type="button"
                        onClick={() => handleIncrement(plan.key)}
                        className="h-8 w-8 rounded-md border border-white/20 text-lg leading-none text-white hover:bg-white/10"
                      >
                        +
                      </button>
                    </div>

                    <div className="mt-3 text-sm text-white/70">
                      Estimated monthly total
                    </div>
                    <div className="text-2xl font-semibold text-cyan-200">
                      ${total} USD
                    </div>
                  </div>

                  <ul className="mt-4 space-y-2 text-sm text-white/80">
                    {plan.features.map((feature) => (
                      <li
                        key={feature}
                        className="flex items-center gap-2"
                      >
                        <CheckIcon className="h-4 w-4" />
                        {feature}
                      </li>
                    ))}
                  </ul>

                  <button
                    type="button"
                    onClick={() => handleSelectPlan(plan)}
                    className="mt-6 rounded-lg border border-cyan-300/40 bg-cyan-950/50 px-4 py-2 text-sm text-cyan-100 hover:bg-cyan-900/60"
                  >
                    Select {plan.name}
                  </button>
                </div>
              );
            })}
          </div>

          <div className="mt-8 flex justify-center">
            <button
              type="button"
              onClick={() => navigate("/organization")}
              className="rounded-lg border border-white/15 px-4 py-2 text-sm text-white/90 hover:bg-white/10"
            >
              Back to organization
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
