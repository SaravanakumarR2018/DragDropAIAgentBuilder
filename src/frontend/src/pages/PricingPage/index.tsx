import { useOrganization, useUser } from "@clerk/clerk-react";
import axios from "axios";
import type { SVGProps } from "react";
import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import planConfigData from "../../../public/plan_config.json";
import { getURL } from "../../controllers/API/helpers/constants";

const MIN_SEATS = 1;
const PADDLE_PRICE_CACHE_KEY = "pricing_page_paddle_prices";
const PADDLE_PRICE_CACHE_TTL_MS = 60 * 60 * 1000;
const PADDLE_STATUS_STORAGE_KEY = "paddle_checkout_status";
const PADDLE_TRANSACTION_ID_STORAGE_KEY = "paddle_checkout_transaction_id";
const PADDLE_CHECKOUT_ORG_ID_STORAGE_KEY = "paddle_checkout_org_id";

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

function SuccessStatusIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" {...props}>
      <circle cx="12" cy="12" r="10" fill="currentColor" />
      <path
        d="M17.207 8.793a1 1 0 0 1 0 1.414l-5.5 5.5a1 1 0 0 1-1.414 0l-2.5-2.5a1 1 0 1 1 1.414-1.414l1.793 1.793 4.793-4.793a1 1 0 0 1 1.414 0z"
        fill="white"
      />
    </svg>
  );
}

function FailedStatusIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" {...props}>
      <circle cx="12" cy="12" r="10" fill="currentColor" />
      <path
        d="M8.707 8.707a1 1 0 0 1 1.414 0L12 10.586l1.879-1.879a1 1 0 1 1 1.414 1.414L13.414 12l1.879 1.879a1 1 0 0 1-1.414 1.414L12 13.414l-1.879 1.879a1 1 0 0 1-1.414-1.414L10.586 12 8.707 10.121a1 1 0 0 1 0-1.414z"
        fill="white"
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
  const [checkoutStatus, setCheckoutStatus] = useState<
    "idle" | "processing" | "success" | "failed"
  >("idle");
  const [transactionId, setTransactionId] = useState<string | null>(null);
  const [redirectCountdown, setRedirectCountdown] = useState(3);
  const currentOrganizationId = organization?.id ?? null;

  const clearCheckoutState = useCallback(() => {
    window.sessionStorage.removeItem(PADDLE_STATUS_STORAGE_KEY);
    window.sessionStorage.removeItem(PADDLE_TRANSACTION_ID_STORAGE_KEY);
    window.sessionStorage.removeItem(PADDLE_CHECKOUT_ORG_ID_STORAGE_KEY);
    setCheckoutStatus("idle");
    setTransactionId(null);
  }, []);

  useEffect(() => {
    const storedOrganizationId = window.sessionStorage.getItem(
      PADDLE_CHECKOUT_ORG_ID_STORAGE_KEY,
    );

    if (
      storedOrganizationId &&
      currentOrganizationId &&
      storedOrganizationId !== currentOrganizationId
    ) {
      clearCheckoutState();
      return;
    }

    const statusFromStorage =
      window.sessionStorage.getItem(PADDLE_STATUS_STORAGE_KEY) ?? "idle";
    if (
      statusFromStorage === "processing" ||
      statusFromStorage === "success" ||
      statusFromStorage === "failed"
    ) {
      setCheckoutStatus(statusFromStorage);
    } else {
      setCheckoutStatus("idle");
    }

    const storedTransactionId = window.sessionStorage.getItem(
      PADDLE_TRANSACTION_ID_STORAGE_KEY,
    );
    setTransactionId(storedTransactionId);
  }, [clearCheckoutState, currentOrganizationId]);

  useEffect(() => {
    const onStatusChange = (event: Event) => {
      const customEvent = event as CustomEvent<{
        status: "idle" | "processing" | "success" | "failed";
        transactionId: string | null;
        organizationId: string | null;
      }>;
      const status = customEvent.detail?.status ?? "idle";
      const latestTransactionId = customEvent.detail?.transactionId ?? null;
      const eventOrganizationId = customEvent.detail?.organizationId ?? null;

      if (
        eventOrganizationId &&
        currentOrganizationId &&
        eventOrganizationId !== currentOrganizationId
      ) {
        return;
      }

      setCheckoutStatus(status);
      setTransactionId(latestTransactionId);
    };

    window.addEventListener("paddle-checkout-status", onStatusChange as EventListener);
    return () => {
      window.removeEventListener(
        "paddle-checkout-status",
        onStatusChange as EventListener,
      );
    };
  }, [currentOrganizationId]);

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
    if (checkoutStatus !== "success") {
      setRedirectCountdown(3);
      return;
    }

    setRedirectCountdown(3);
    const intervalId = window.setInterval(() => {
      setRedirectCountdown((prev) => {
        if (prev <= 1) {
          window.clearInterval(intervalId);
          clearCheckoutState();
          navigate("/flows");
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, [checkoutStatus, clearCheckoutState, navigate]);

  const handleCloseFailureModal = () => {
    clearCheckoutState();
  };

  const handleContinueToFlows = () => {
    clearCheckoutState();
    navigate("/flows");
  };

  const handleSelectPlan = async (plan: PlanConfig) => {
    const seats = seatsByPlan[plan.key];
    setSelectedPlan(plan.key);
    setShowEnterpriseContactMessage(false);
    clearCheckoutState();

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

  useEffect(() => {
    if (checkoutStatus !== "failed") {
      return;
    }

    const statusFromStorage = window.sessionStorage.getItem(PADDLE_STATUS_STORAGE_KEY);
    if (statusFromStorage !== "failed") {
      return;
    }

    const storedOrganizationId = window.sessionStorage.getItem(
      PADDLE_CHECKOUT_ORG_ID_STORAGE_KEY,
    );
    if (
      storedOrganizationId &&
      currentOrganizationId &&
      storedOrganizationId !== currentOrganizationId
    ) {
      clearCheckoutState();
      return;
    }

    const storedTransactionId = window.sessionStorage.getItem(
      PADDLE_TRANSACTION_ID_STORAGE_KEY,
    );
    if (storedTransactionId) {
      setTransactionId(storedTransactionId);
    }
  }, [checkoutStatus, clearCheckoutState, currentOrganizationId]);

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
      {checkoutStatus === "processing" && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 px-4">
          <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl">
            <h2 className="text-xl font-semibold text-slate-900">
              Payment is processing
            </h2>
            <p className="mt-3 text-sm text-slate-600">
              Please wait while we confirm your subscription status.
            </p>
            <div className="mt-6 h-2 w-full overflow-hidden rounded-full bg-slate-200">
              <div className="h-full w-1/2 animate-pulse rounded-full bg-slate-900" />
            </div>
          </div>
        </div>
      )}
      {(checkoutStatus === "success" || checkoutStatus === "failed") && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 px-4">
          <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow-2xl">
            <h2 className="text-xl font-semibold text-slate-900">
              {checkoutStatus === "success"
                ? "Payment successful"
                : "Payment failed"}
            </h2>
            <div className="mb-4 flex justify-center">
              {checkoutStatus === "success" ? (
                <SuccessStatusIcon className="h-12 w-12 text-emerald-500" />
              ) : (
                <FailedStatusIcon className="h-12 w-12 text-red-500" />
              )}
            </div>
            <p className="mt-3 text-sm text-slate-600">
              {checkoutStatus === "success"
                ? `Redirecting to flows in ${redirectCountdown} seconds.`
                : "We couldn't verify an active subscription for this payment."}
            </p>
            {checkoutStatus === "failed" && transactionId && (
              <p className="mt-2 text-xs text-slate-500">
                Transaction ID: {transactionId}
              </p>
            )}
            <div className="mt-6 flex justify-end gap-3">
              {checkoutStatus === "failed" && (
                <button
                  type="button"
                  onClick={handleCloseFailureModal}
                  className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 transition hover:border-sky-300 hover:text-sky-700"
                >
                  Stay on pricing
                </button>
              )}
              <button
                type="button"
                onClick={
                  checkoutStatus === "success"
                    ? handleContinueToFlows
                    : handleCloseFailureModal
                }
                className="rounded-xl bg-slate-900 px-4 py-2 text-sm font-semibold text-white transition hover:bg-slate-800"
              >
                {checkoutStatus === "success" ? "Go to flows" : "Close"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
