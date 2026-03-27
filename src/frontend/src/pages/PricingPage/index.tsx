import {useOrganization, useUser } from "@clerk/clerk-react";
import axios from "axios";
import type { SVGProps } from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import planConfigData from "../../../public/plan_config.json";
import { getURL } from "../../controllers/API/helpers/constants";

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
    plan_key:
      | "starter_pack_monthly"
      | "pro_pack_monthly"
      | "enterprise_pack_monthly";
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
  paddlePlanKey:
    | "starter_pack_monthly"
    | "pro_pack_monthly"
    | "enterprise_pack_monthly";
  defaultSeats: number;
}

const STATIC_PLANS: PlanConfig[] = (
  planConfigData.plans as SharedPlanConfig[]
).map((plan) => ({
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
  const { organization } = useOrganization();
  const email = user?.primaryEmailAddress?.emailAddress;
  const [showEnterpriseContactMessage, setShowEnterpriseContactMessage] =
    useState(false);

  const [selectedPlan, setSelectedPlan] = useState<PlanKey>("starter");
  const [seatsByPlan, setSeatsByPlan] = useState<Record<PlanKey, number>>({
    starter:
      STATIC_PLANS.find((plan) => plan.key === "starter")?.defaultSeats ?? 1,
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
        org_id: organization?.id,
      },
    });
  };

  return (
    <div className="w-full overflow-x-hidden">
      <div className="min-h-screen px-4 py-12 text-slate-900">
        <div className="mx-auto w-full max-w-5xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 sm:p-8 shadow-lg">
            <div className="text-center">
              <h1 className="text-2xl sm:text-3xl lg:text-4xl font-semibold">
                Simple, scalable pricing
              </h1>
            </div>

            <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
              {STATIC_PLANS.map((plan) => {
                const seats = seatsByPlan[plan.key];
                const total = seats * plan.pricePerSeat;

                return (
                  <div
                    key={plan.key}
                    className={`flex flex-col rounded-2xl border p-5 sm:p-6 transition-all ${
                      selectedPlan === plan.key
                        ? "border-sky-400 bg-sky-50/80 shadow-[0_18px_45px_rgba(14,165,233,0.12)]"
                        : "border-slate-200 bg-white shadow-sm"
                    }`}
                  >
                    <div className="text-sm font-medium uppercase tracking-[0.18em] text-slate-500">
                      {plan.name}
                    </div>
                    <div className="mt-2 text-3xl font-semibold text-slate-900">
                      ${plan.pricePerSeat}/seat/month
                    </div>

                    {plan.hasTrial && (
                      <div className="mt-1 text-sm font-medium text-sky-700">
                        {plan.trialDays}-day free trial
                      </div>
                    )}

                    <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                      <div className="text-xs uppercase tracking-[0.18em] text-slate-500">
                        Seats
                      </div>

                      <div className="mt-2 flex items-center gap-3">
                        <button
                          type="button"
                          onClick={() => handleDecrement(plan.key)}
                          className="h-9 w-9 rounded-xl border border-slate-200 bg-white text-lg text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
                        >
                          -
                        </button>

                        <span className="min-w-8 text-center text-xl font-semibold text-slate-900">
                          {seats}
                        </span>

                        <button
                          type="button"
                          onClick={() => handleIncrement(plan.key)}
                          className="h-9 w-9 rounded-xl border border-slate-200 bg-white text-lg text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
                        >
                          +
                        </button>
                      </div>

                      <div className="mt-3 text-sm text-slate-500">
                        Estimated monthly total
                      </div>
                      <div className="text-2xl font-semibold text-slate-900">
                        ${total} USD
                      </div>
                    </div>

                    <ul className="mt-5 space-y-3 text-sm text-slate-600">
                      {plan.features.map((feature) => (
                        <li key={feature} className="flex items-center gap-2">
                          <CheckIcon className="h-4 w-4 text-sky-600" />
                          {feature}
                        </li>
                      ))}
                    </ul>

                    <button
                      type="button"
                      onClick={() => handleSelectPlan(plan)}
                      className={`mt-6 rounded-xl px-4 py-3 text-sm font-semibold transition ${
                        plan.key === "enterprise"
                          ? "border border-slate-200 bg-white text-slate-700 hover:border-sky-300 hover:text-sky-700"
                          : "bg-slate-900 text-white hover:bg-slate-800"
                      }`}
                    >
                      Select {plan.name}
                    </button>
                  </div>
                );
              })}
            </div>

            <div className="mt-8 flex flex-wrap justify-center gap-3">
              <button
                type="button"
                onClick={() => {
                  navigate("/flows?pricing_bypass=1");
                }}
                className="rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-slate-800"
              >
                Go to flows
              </button>
              <button
                type="button"
                onClick={() => navigate("/organization")}
                className="rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
              >
                Back to organization
              </button>
            </div>

            {showEnterpriseContactMessage && (
              <p className="mt-5 text-center text-sm font-medium text-sky-700">
                For Enterprise plans, please contact us.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
