import { useAuth, useUser } from "@clerk/clerk-react";
import axios from "axios";
import type { SVGProps } from "react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getURL } from "../../controllers/API/helpers/constants";
import planConfigData from "../../../public/plan_config.json";

const MIN_SEATS = 1;
const PADDLE_PRICE_CACHE_KEY = "pricing_page_paddle_prices";
const PADDLE_PRICE_CACHE_TTL_MS = 60 * 60 * 1000;
const BILLING_SUBSCRIPTION_STORAGE_KEY = "paddle_subscription_id";

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
  const { getToken } = useAuth();
  const email = user?.primaryEmailAddress?.emailAddress;
  const [showEnterpriseContactMessage, setShowEnterpriseContactMessage] =
    useState(false);
  const [showStarterTrialModal, setShowStarterTrialModal] = useState(false);
  const [trialSeats, setTrialSeats] = useState(MIN_SEATS);
  const [trialPostalCode, setTrialPostalCode] = useState("");
  const [trialCountry, setTrialCountry] = useState("");
  const [manualCountry, setManualCountry] = useState("");

  const [selectedPlan, setSelectedPlan] = useState<PlanKey>("starter");
  const [seatsByPlan, setSeatsByPlan] = useState<Record<PlanKey, number>>({
    starter: STATIC_PLANS.find((plan) => plan.key === "starter")?.defaultSeats ?? 1,
    pro: STATIC_PLANS.find((plan) => plan.key === "pro")?.defaultSeats ?? 1,
    enterprise:
      STATIC_PLANS.find((plan) => plan.key === "enterprise")?.defaultSeats ?? 5,
  });

  const [priceMap, setPriceMap] = useState<Record<string, string>>({});
  const [loadingPrices, setLoadingPrices] = useState(true);

  const existingSubscriptionId =
    (user?.publicMetadata?.paddle_subscription_id as string | undefined)?.trim() ||
    window.localStorage.getItem(BILLING_SUBSCRIPTION_STORAGE_KEY) ||
    null;

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

  useEffect(() => {
    const detectCountry = async () => {
      try {
        const res = await axios.get("https://ipapi.co/json/");
        const detectedCountry = res.data?.country_name;

        if (detectedCountry) {
          setTrialCountry(detectedCountry);
        }
      } catch (err) {
        console.warn("Unable to detect country via ipapi", err);
      }
    };

    detectCountry();
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

    if (
      plan.paddlePlanKey === "starter_pack_monthly" &&
      !existingSubscriptionId
    ) {
      setTrialSeats(seats);
      setShowStarterTrialModal(true);
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

  const handleConfirmStarterTrial = async () => {
    const starterPlanKey = "starter_pack_monthly";
    const finalCountry =
      manualCountry.trim().length > 0
        ? manualCountry.trim()
            .toLowerCase()
            .replace(/\b\w/g, (c) => c.toUpperCase())
        : trialCountry;

    try {
      const token = await getToken();
      if (!token) {
        console.error("Unable to start trial: missing auth token");
        return;
      }

      const { data } = await axios.post(
        getURL("START_TRIAL"),
        {
          plan_key: starterPlanKey,
          seats: trialSeats,
          country: finalCountry,
          postal_code: trialPostalCode,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      if (data?.subscription_id) {
        window.localStorage.setItem(
          BILLING_SUBSCRIPTION_STORAGE_KEY,
          data.subscription_id,
        );
      }

      setShowStarterTrialModal(false);
      navigate("/flows");
    } catch (error) {
      console.error("Failed to start Starter Pack trial", error);
    }
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
          {showStarterTrialModal && (
            <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
              <div className="w-full max-w-md rounded-xl border border-white/10 bg-[#0f1217] p-6">
                <h2 className="text-lg font-semibold">Start Starter Trial</h2>
                <p className="mt-1 mb-4 text-sm text-white/70">
                  Confirm your details to start your free trial.
                </p>

                <label className="text-sm text-white/70">Country</label>
                <select
                  value={trialCountry}
                  onChange={(e) => setTrialCountry(e.target.value)}
                  className="w-full mt-1 mb-4 bg-black border border-white/10 rounded p-2"
                >
                  <option value="United States">United States</option>
                  <option value="India">India</option>
                  <option value="United Kingdom">United Kingdom</option>
                  <option value="Canada">Canada</option>
                  <option value="Germany">Germany</option>
                  <option value="France">France</option>
                  <option value="Australia">Australia</option>
                </select>

                <label className="text-sm text-white/70">Country (type if not listed)</label>
                <input
                  type="text"
                  value={manualCountry}
                  onChange={(e) => setManualCountry(e.target.value)}
                  placeholder="Type your country"
                  className="w-full mt-1 mb-4 bg-black border border-white/10 rounded p-2"
                />

                <label className="text-sm text-white/70">Postal code</label>
                <input
                  type="text"
                  value={trialPostalCode}
                  onChange={(e) => setTrialPostalCode(e.target.value)}
                  placeholder="Enter postal code"
                  className="w-full mt-1 mb-4 bg-black border border-white/10 rounded p-2"
                />

                <div className="flex justify-end gap-2">
                  <button
                    type="button"
                    onClick={() => setShowStarterTrialModal(false)}
                    className="rounded-lg border border-white/20 px-4 py-2 text-sm"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={handleConfirmStarterTrial}
                    className="rounded-lg border border-cyan-300/40 px-4 py-2 text-sm"
                  >
                    Start trial
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
