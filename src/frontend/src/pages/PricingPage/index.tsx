import { useUser } from "@clerk/clerk-react";
import axios from "axios";
import type { SVGProps } from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getURL } from "../../controllers/API/helpers/constants";

const MIN_SEATS = 1;

type PlanKey = "starter" | "pro" | "enterprise";

const PLAN_KEY_MAP: Record<
  PlanKey,
  "starter_pack_monthly" | "pro_pack_monthly" | "enterprise_pack_monthly"
> = {
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

const STATIC_PLANS: PlanConfig[] = [
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
  const { user } = useUser();
  const email = user?.primaryEmailAddress?.emailAddress;
  const [showEnterpriseContactMessage, setShowEnterpriseContactMessage] =
    useState(false);

  const [selectedPlan, setSelectedPlan] = useState<PlanKey>("starter");
  const [seatsByPlan, setSeatsByPlan] = useState<Record<PlanKey, number>>({
    starter: 1,
    pro: 1,
    enterprise: 5,
  });

  const [priceMap, setPriceMap] = useState<Record<string, string>>({});
  const [loadingPrices, setLoadingPrices] = useState(true);

  useEffect(() => {
    const fetchPrices = async () => {
      try {
        const { data } = await axios.get(getURL("GET_PADDLE_PRICES"));
        setPriceMap(data ?? {});
      } catch (err) {
        console.error("Failed to load Paddle price IDs:", err);
      } finally {
        setLoadingPrices(false);
      }
    };

    fetchPrices();
  }, []);

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
    const seats = seatsByPlan[plan.key];
    setSelectedPlan(plan.key);
    setShowEnterpriseContactMessage(false);

    if (plan.key === "enterprise") {
      setShowEnterpriseContactMessage(true);
      return;
    }

    if (loadingPrices) {
      console.warn("Paddle prices are still loading. Please try again.");
      return;
    }

    const planKey = PLAN_KEY_MAP[plan.key];
    const priceId = priceMap[planKey];

    if (!priceId) {
      console.error("Missing Paddle price ID for:", planKey);
      return;
    }

    if (!window.Paddle) {
      console.error("Paddle is not initialized");
      return;
    }
    if (!email) {
      console.error("User email not available");
      return;
    }

    window.Paddle.Checkout.open({
      items: [
        {
          priceId,
          quantity: seats,
        },
      ],
      customer: {
        email,
      },
      settings: {
        allowLogout: false,
      },
      customData: {
        plan_key: planKey,
        seats,
      },
    });
  };

  return (
    <div className="min-h-screen bg-[#0f1217] px-4 py-14 text-white">
      <div className="mx-auto max-w-7xl">
        <div className="rounded-2xl border border-white/10 bg-[#0f1217] p-8">
          <div className="text-center">
            <h1 className="text-2xl font-semibold">Simple, Scalable Pricing</h1>
            <p className="mt-3 text-white/70">
              Choose the plan that matches your team size and scale with
              confidence.
            </p>
          </div>

          <div className="mt-10 grid gap-6 md:grid-cols-3">
            {STATIC_PLANS.map((plan) => {
              const seats = seatsByPlan[plan.key];
              const total = seats * plan.pricePerSeat;

              return (
                <div
                  key={plan.key}
                  className={`flex flex-col rounded-xl border p-6 ${
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
                    <div className="text-xs uppercase text-white/60">Seats</div>

                    <div className="mt-2 flex items-center gap-3">
                      <button
                        type="button"
                        onClick={() => handleDecrement(plan.key)}
                        className="h-8 w-8 rounded-md border border-white/20"
                      >
                        -
                      </button>

                      <span className="text-xl font-semibold">{seats}</span>

                      <button
                        type="button"
                        onClick={() => handleIncrement(plan.key)}
                        className="h-8 w-8 rounded-md border border-white/20"
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
                      <li key={feature} className="flex items-center gap-2">
                        <CheckIcon className="h-4 w-4" />
                        {feature}
                      </li>
                    ))}
                  </ul>

                  <button
                    type="button"
                    onClick={() => handleSelectPlan(plan)}
                    className="mt-6 rounded-lg border border-cyan-300/40 px-4 py-2 text-sm"
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
              onClick={() => {
                sessionStorage.setItem("pricingBypass", "1");
                navigate("/flows");
              }}
              className="mr-3 rounded-lg border border-cyan-300/40 px-4 py-2 text-sm"
            >
              Temporary: Go to flows
            </button>
            <button
              type="button"
              onClick={() => navigate("/organization")}
              className="rounded-lg border border-white/15 px-4 py-2 text-sm"
            >
              Back to organization
            </button>
          </div>

          {showEnterpriseContactMessage && (
            <p className="mt-4 text-center text-sm text-cyan-300">
              For Enterprise plans, please contact us.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
