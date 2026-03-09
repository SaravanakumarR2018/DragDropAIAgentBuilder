import { useUser } from "@clerk/clerk-react";
import axios from "axios";
import type { SVGProps } from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getURL } from "../../controllers/API/helpers/constants";
import planConfigData from "../../common/plan_config.json";

const MIN_SEATS = 1;
const PADDLE_PRICE_CACHE_KEY = "pricing_page_paddle_prices";
const PADDLE_PRICE_CACHE_TTL_MS = 60 * 60 * 1000;

type PlanKey = "starter" | "pro" | "enterprise";

interface SharedPlanConfig {
  key: PlanKey;
  name: string;
  default_seats: number;
  features: string[];
  paddle: {
    enabled: boolean;
    plan_key: "starter_pack_monthly" | "pro_pack_monthly" | "enterprise_pack_monthly";
    monthly_price_usd_cents: number;
    trial_days: number | null;
  };
}

interface CachedPriceMap {
  fetchedAt: number;
  prices: Record<string, string>;
}

function getCachedPriceMap(): Record<string, string> | null {
  try {
    const raw = window.localStorage.getItem(PADDLE_PRICE_CACHE_KEY);
    if (!raw) return null;

    const parsed = JSON.parse(raw) as CachedPriceMap;
    const isExpired = Date.now() - parsed.fetchedAt > PADDLE_PRICE_CACHE_TTL_MS;

    if (isExpired) {
      window.localStorage.removeItem(PADDLE_PRICE_CACHE_KEY);
      return null;
    }

    return parsed.prices ?? null;
  } catch {
    window.localStorage.removeItem(PADDLE_PRICE_CACHE_KEY);
    return null;
  }
}

function setCachedPriceMap(prices: Record<string, string>): void {
  const payload: CachedPriceMap = {
    fetchedAt: Date.now(),
    prices,
  };
  window.localStorage.setItem(PADDLE_PRICE_CACHE_KEY, JSON.stringify(payload));
}

interface PlanConfig {
  key: PlanKey;
  name: string;
  pricePerSeat: number;
  hasTrial: boolean;
  trialDays?: number;
  features: string[];
  paddlePlanKey: "starter_pack_monthly" | "pro_pack_monthly" | "enterprise_pack_monthly";
  defaultSeats: number;
}

const STATIC_PLANS: PlanConfig[] = (planConfigData.plans as SharedPlanConfig[]).map((plan) => ({
  key: plan.key,
  name: plan.name,
  pricePerSeat: plan.paddle.monthly_price_usd_cents / 100,
  hasTrial: plan.paddle.trial_days !== null,
  trialDays: plan.paddle.trial_days ?? undefined,
  features: plan.features,
  paddlePlanKey: plan.paddle.plan_key,
  defaultSeats: plan.default_seats,
}));

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
    starter: STATIC_PLANS.find((plan) => plan.key === "starter")?.defaultSeats ?? 1,
    pro: STATIC_PLANS.find((plan) => plan.key === "pro")?.defaultSeats ?? 1,
    enterprise:
      STATIC_PLANS.find((plan) => plan.key === "enterprise")?.defaultSeats ?? 5,
  });

  const [priceMap, setPriceMap] = useState<Record<string, string>>({});
  const [loadingPrices, setLoadingPrices] = useState(true);

  useEffect(() => {
    const fetchPrices = async () => {
      const cachedPrices = getCachedPriceMap();
      if (cachedPrices) {
        setPriceMap(cachedPrices);
        setLoadingPrices(false);
        return;
      }

      try {
        const { data } = await axios.get(getURL("GET_PADDLE_PRICES"));
        const freshPrices = data ?? {};
        setPriceMap(freshPrices);
        setCachedPriceMap(freshPrices);
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

    const planKey = plan.paddlePlanKey;
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
                navigate("/flows?pricing_bypass=1");
              }}
              className="mr-3 rounded-lg border border-cyan-300/40 px-4 py-2 text-sm"
            >
             Go to flows
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
