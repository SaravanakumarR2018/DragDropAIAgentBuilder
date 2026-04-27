import { useAuth } from "@clerk/clerk-react";
import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import Loading from "@/components/ui/loading";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import planConfigData from "../../../public/plan_config.json";
import { useChangePlan, useChangeSeats, usePreviewChange } from "./hooks";

type PlanKey = "starter" | "pro" | "enterprise";

type BillingAccessResponse = {
  has_access?: boolean;
  is_admin?: boolean;
  subscription_status?: string | null;
  subscription_plan_key?: string | null;
  subscription_seats?: number | null;
  seats?: number | null;
  quantity?: number | null;
  next_billed_at?: string | null;
};

type PaddlePricesResponse = Record<string, string>;

type PlanConfig = {
  key: PlanKey;
  name: string;
  features: string[];
  monthlyPriceUsdCents: number;
  paddlePlanKey: string;
};

const MIN_SEATS = 1;
const ENTERPRISE_PLAN_KEY: PlanKey = "enterprise";

const STATIC_PLANS: PlanConfig[] = (planConfigData.plans ?? []).map((plan) => ({
  key: String(plan?.key ?? "") as PlanKey,
  name: String(plan?.name ?? "").trim(),
  features: (plan?.features ?? []).map((feature) => String(feature)),
  monthlyPriceUsdCents: Number(plan?.paddle?.monthly_price_usd_cents ?? 0),
  paddlePlanKey: String(plan?.paddle?.plan_key ?? "").toLowerCase(),
}));

function CheckIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      aria-hidden="true"
      className="h-4 w-4 text-sky-600"
    >
      <path
        d="M20.285 6.709a1 1 0 0 1 0 1.414l-9.192 9.192a1 1 0 0 1-1.414 0L3.715 11.55a1 1 0 0 1 1.414-1.415l5.136 5.136 8.485-8.485a1 1 0 0 1 1.535-.077z"
        fill="currentColor"
      />
    </svg>
  );
}

function extractPreviewAmount(previewData: any): number | null {
  if (!previewData) return null;

  const summaryAmount = previewData?.update_summary?.result?.amount;
  if (summaryAmount) {
    return Number(summaryAmount) / 100;
  }

  const immediateAmount =
    previewData?.immediate_transaction?.details?.totals?.total;

  if (immediateAmount) {
    return Number(immediateAmount) / 100;
  }

  return null;
}

function toCurrency(amount: number): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  }).format(amount);
}

export default function ChangePlansPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { getToken } = useAuth();
  const [mode, setMode] = useState<"plan" | "seats">("plan");

  const previewChange = usePreviewChange();
  const changePlan = useChangePlan();
  const changeSeats = useChangeSeats();

  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [billing, setBilling] = useState<BillingAccessResponse | null>(null);
  const [priceMap, setPriceMap] = useState<PaddlePricesResponse>({});
  const [currentPlanKey, setCurrentPlanKey] = useState<string>("");
  const [currentSeats, setCurrentSeats] = useState<number>(1);
  const [selectedPlanKey, setSelectedPlanKey] = useState<string>("");
  const [pendingSeats, setPendingSeats] = useState<number>(1);
  const [previewData, setPreviewData] = useState<unknown>(null);
  const [previewMessage, setPreviewMessage] = useState<string | null>(null);
  const [summaryMessage, setSummaryMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const getPlanByKey = (planKey: string) =>
    STATIC_PLANS.find((plan) => plan.key === planKey) ?? null;

  const isDowngradePlanSelection = (nextPlanKey: string) => {
    const currentPlan = getPlanByKey(currentPlanKey);
    const nextPlan = getPlanByKey(nextPlanKey);

    if (!currentPlan || !nextPlan) {
      return false;
    }

    return nextPlan.monthlyPriceUsdCents < currentPlan.monthlyPriceUsdCents;
  };

  const downgradePlanMessage =
    "You are currently on a higher plan. Please cancel your current subscription to switch plans at the end of the billing cycle.";

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const nextMode = params.get("mode") === "seats" ? "seats" : "plan";
    setMode(nextMode);
    setErrorMessage(null);
    setPreviewData(null);
    setPreviewMessage(null);
    setSummaryMessage(null);
    setConfirmOpen(false);
  }, [location.search]);

  useEffect(() => {
    if (mode === "seats") {
      setSelectedPlanKey(currentPlanKey);
      setPendingSeats(Math.max(MIN_SEATS, currentSeats));
    }
  }, [currentPlanKey, currentSeats, mode]);

  const isCancelled = ["cancelled", "canceled"].includes(
    String(billing?.subscription_status ?? "").toLowerCase(),
  );
  const isAdmin = Boolean(billing?.is_admin);
  const actionsBlocked = isCancelled || !isAdmin;

  useEffect(() => {
    let mounted = true;

    const load = async () => {
      setLoading(true);
      try {
        const token = await getToken();
        if (!token) {
          throw new Error("Missing auth token");
        }

        const [billingRes, pricesRes] = await Promise.all([
          api.get(getURL("BILLING_ACCESS"), {
            headers: { Authorization: `Bearer ${token}` },
          }),
          api.get(getURL("GET_PADDLE_PRICES"), {
            headers: { Authorization: `Bearer ${token}` },
          }),
        ]);

        if (!mounted) {
          return;
        }

        const billingData = (billingRes.data ??
          null) as BillingAccessResponse | null;
        setBilling(billingData);

        const subscribedPaddlePlanKey = String(
          billingData?.subscription_plan_key ?? "",
        ).toLowerCase();
        const matchedPlan =
          STATIC_PLANS.find(
            (plan) => plan.paddlePlanKey === subscribedPaddlePlanKey,
          ) ??
          STATIC_PLANS.find((plan) => plan.key === subscribedPaddlePlanKey) ??
          null;
        const normalizedPlanKey = matchedPlan?.key ?? subscribedPaddlePlanKey;
        const seats =
          Number(
            billingData?.subscription_seats ??
              billingData?.seats ??
              billingData?.quantity ??
              MIN_SEATS,
          ) || MIN_SEATS;

        setCurrentPlanKey(normalizedPlanKey);
        setSelectedPlanKey(normalizedPlanKey);
        setCurrentSeats(Math.max(MIN_SEATS, seats));
        setPendingSeats(Math.max(MIN_SEATS, seats));
        setPriceMap((pricesRes.data ?? {}) as PaddlePricesResponse);
      } catch (error: any) {
        if (mounted) {
          setErrorMessage(
            String(
              error?.response?.data?.detail ??
                error?.message ??
                "Failed to load billing data.",
            ),
          );
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    void load();
    return () => {
      mounted = false;
    };
  }, [getToken]);

  const handleSeatDecrement = () => {
    setPendingSeats((prev) => Math.max(MIN_SEATS, prev - 1));
  };

  const handleSeatIncrement = () => {
    setPendingSeats((prev) => prev + 1);
  };

  function buildPreviewMessage(
    previewData: any,
    nextBillingDate?: string,
  ): string | null {
    if (!previewData) return null;

    const hasImmediateCharge = Boolean(previewData?.immediate_transaction);
    const amount = extractPreviewAmount(previewData);

    if (hasImmediateCharge && amount !== null) {
      return `You will be charged ${toCurrency(amount)} today.`;
    }

    if (nextBillingDate) {
      const date = new Date(nextBillingDate);
      const formatted = date.toLocaleDateString(undefined, {
        dateStyle: "medium",
      });
      return `Your plan will change on ${formatted}. No charge today.`;
    }

    return "This change will take effect on your next billing date. No charge today.";
  }

  const handlePlanSelect = async (planKey: string) => {
    if (mode !== "plan" || actionsBlocked || planKey === currentPlanKey) {
      return;
    }

    setSelectedPlanKey(planKey);
    setErrorMessage(null);
    setSummaryMessage(null);
    setPreviewData(null);
    setPreviewMessage(null);

    if (planKey === ENTERPRISE_PLAN_KEY) {
      setSummaryMessage("Please contact us to switch to the Enterprise plan.");
      return;
    }

    if (isDowngradePlanSelection(planKey)) {
      setSummaryMessage(downgradePlanMessage);
      return;
    }

    try {
      const selected = STATIC_PLANS.find((plan) => plan.key === planKey);
      const selectedPriceId = selected
        ? priceMap[selected.paddlePlanKey]
        : undefined;

      if (!selectedPriceId) {
        throw new Error("Missing price id for selected plan.");
      }

      const preview = await previewChange({
        price_id: selectedPriceId,
        seats: currentSeats,
      });

      setPreviewData(preview);
      setPreviewMessage(buildPreviewMessage(preview, billing?.next_billed_at));
      setSummaryMessage(
        `Plan change: ${currentPlanKey || "current"} → ${planKey} (${currentSeats} seats).`,
      );
    } catch (error: any) {
      setErrorMessage(
        String(
          error?.response?.data?.detail ??
            error?.message ??
            "Failed to preview plan change.",
        ),
      );
    }
  };

  const handlePreviewBeforeConfirm = async () => {
    if (actionsBlocked) {
      return;
    }

    setErrorMessage(null);

    try {
      if (mode === "seats") {
        const preview = await previewChange({ seats: pendingSeats });
        setPreviewData(preview);
        setPreviewMessage(
          buildPreviewMessage(preview, billing?.next_billed_at),
        );
      } else {
        if (selectedPlanKey === ENTERPRISE_PLAN_KEY) {
          setSummaryMessage(
            "Please contact us to switch to the Enterprise plan.",
          );
          return;
        }

        if (isDowngradePlanSelection(selectedPlanKey)) {
          setSummaryMessage(downgradePlanMessage);
          return;
        }

        const selected = STATIC_PLANS.find(
          (plan) => plan.key === selectedPlanKey,
        );
        const selectedPriceId = selected
          ? priceMap[selected.paddlePlanKey]
          : undefined;

        if (!selectedPriceId) {
          throw new Error("Missing price id for selected plan.");
        }

        const preview = await previewChange({
          price_id: selectedPriceId,
          seats: currentSeats,
        });

        setPreviewData(preview);
        setPreviewMessage(
          buildPreviewMessage(preview, billing?.next_billed_at),
        );
        setSummaryMessage(
          `Plan change: ${currentPlanKey || "current"} → ${selectedPlanKey} (${currentSeats} seats).`,
        );
      }

      setConfirmOpen(true);
    } catch (error: any) {
      setErrorMessage(
        String(
          error?.response?.data?.detail ??
            error?.message ??
            "Failed to preview changes before confirmation.",
        ),
      );
    }
  };

  const handleConfirm = async () => {
    if (actionsBlocked) {
      return;
    }

    setSubmitting(true);
    setErrorMessage(null);

    try {
      if (mode === "seats") {
        await changeSeats({ seats: pendingSeats });
        setCurrentSeats(pendingSeats);
      } else {
        if (selectedPlanKey === ENTERPRISE_PLAN_KEY) {
          setSummaryMessage(
            "Please contact us to switch to the Enterprise plan.",
          );
          setConfirmOpen(false);
          return;
        }

        const selected = STATIC_PLANS.find(
          (plan) => plan.key === selectedPlanKey,
        );
        const selectedPriceId = selected
          ? priceMap[selected.paddlePlanKey]
          : undefined;

        if (!selectedPriceId) {
          throw new Error("Missing price id for selected plan.");
        }

        await changePlan({
          price_id: selectedPriceId,
          seats: currentSeats,
        });
        setCurrentPlanKey(selectedPlanKey);
      }

      setConfirmOpen(false);
      navigate("/settings/pricing-plans", { replace: true });
    } catch (error: any) {
      setErrorMessage(
        String(
          error?.response?.data?.detail ??
            error?.message ??
            "Failed to apply billing change.",
        ),
      );
    } finally {
      setSubmitting(false);
    }
  };

  const canSubmitSeatMode =
    mode === "seats" &&
    !actionsBlocked &&
    pendingSeats >= MIN_SEATS &&
    pendingSeats !== currentSeats;
  const canSubmitPlanMode =
    mode === "plan" &&
    !actionsBlocked &&
    Boolean(selectedPlanKey) &&
    selectedPlanKey !== currentPlanKey &&
    !isDowngradePlanSelection(selectedPlanKey) &&
    selectedPlanKey !== ENTERPRISE_PLAN_KEY;

  return (
    <div className="w-full overflow-x-hidden">
      <div className="min-h-screen px-4 py-12 text-slate-900">
        <div className="mx-auto w-full max-w-5xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-lg sm:p-8">
            <div className="text-center">
              <h1 className="text-2xl font-semibold sm:text-3xl lg:text-4xl">
                {mode === "seats" ? "Change Seats" : "Change Plan"}
              </h1>
              <p className="mt-2 text-sm text-slate-600">
                {mode === "seats"
                  ? "Update seat quantity for your current subscription plan."
                  : "Select a different plan. Seat quantity is fixed during plan changes."}
              </p>
            </div>

            {loading ? (
              <div className="mt-8 flex justify-center">
                <Loading />
              </div>
            ) : (
              <>
                {actionsBlocked && (
                  <div className="mt-6 rounded-xl border border-amber-300 bg-amber-50 p-3 text-sm text-amber-700">
                    Actions are disabled because your subscription is cancelled
                    or you are not an admin.
                  </div>
                )}

                {errorMessage && (
                  <div className="mt-6 rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
                    {errorMessage}
                  </div>
                )}

                {previewMessage && (
                  <div className="mt-6 rounded-xl border border-emerald-300 bg-emerald-50 p-3 text-sm text-emerald-700">
                    {previewMessage}
                  </div>
                )}

                {summaryMessage && (
                  <div className="mt-3 rounded-xl border border-slate-200 bg-slate-50 p-3 text-sm text-slate-700">
                    {summaryMessage}
                  </div>
                )}

                <div className="mt-8 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
                  {STATIC_PLANS.map((plan) => {
                    const isCurrentPlan = plan.key === currentPlanKey;
                    const isSelectedPlan = plan.key === selectedPlanKey;
                    const planDisabledInSeatMode =
                      mode === "seats" && !isCurrentPlan;
                    const isDisabledPlan =
                      actionsBlocked || planDisabledInSeatMode;

                    const borderClass = isCurrentPlan
                      ? "border-emerald-500"
                      : isSelectedPlan
                        ? "border-sky-400"
                        : "border-slate-200";

                    const cardOpacity =
                      mode === "seats" && !isCurrentPlan
                        ? "opacity-50"
                        : "opacity-100";

                    const seatsForCard = isCurrentPlan
                      ? pendingSeats
                      : currentSeats;
                    const total =
                      (seatsForCard * plan.monthlyPriceUsdCents) / 100;
                    const canEditSeats =
                      mode === "seats" && isCurrentPlan && !actionsBlocked;
                    const buttonDisabled =
                      isDisabledPlan || mode === "seats" || isCurrentPlan;

                    return (
                      <div
                        key={plan.key}
                        className={`flex flex-col rounded-2xl border bg-white p-5 shadow-sm transition-all sm:p-6 ${borderClass} ${cardOpacity}`}
                      >
                        <div className="text-sm font-medium uppercase tracking-[0.18em] text-slate-500">
                          {plan.name}
                        </div>
                        <div className="mt-2 text-3xl font-semibold text-slate-900">
                          {(plan.monthlyPriceUsdCents / 100).toLocaleString(
                            "en-US",
                            {
                              style: "currency",
                              currency: "USD",
                              maximumFractionDigits: 0,
                            },
                          )}
                          /seat/month
                        </div>

                        <div className="mt-5 rounded-2xl border border-slate-200 bg-slate-50 p-4">
                          <div className="text-xs uppercase tracking-[0.18em] text-slate-500">
                            Seats
                          </div>

                          <div className="mt-2 flex items-center gap-3">
                            <button
                              type="button"
                              onClick={handleSeatDecrement}
                              disabled={!canEditSeats}
                              className="h-9 w-9 rounded-xl border border-slate-200 bg-white text-lg text-slate-700 transition enabled:hover:border-sky-300 enabled:hover:text-sky-700 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              -
                            </button>

                            <input
                              type="number"
                              min={MIN_SEATS}
                              value={seatsForCard}
                              onChange={(event) => {
                                const next = Number(event.target.value);
                                if (Number.isNaN(next)) {
                                  return;
                                }
                                setPendingSeats(Math.max(MIN_SEATS, next));
                              }}
                              disabled={!canEditSeats}
                              className="w-16 rounded-md border border-slate-200 px-2 py-1 text-center text-lg font-semibold text-slate-900 disabled:cursor-not-allowed disabled:bg-slate-100"
                            />

                            <button
                              type="button"
                              onClick={handleSeatIncrement}
                              disabled={!canEditSeats}
                              className="h-9 w-9 rounded-xl border border-slate-200 bg-white text-lg text-slate-700 transition enabled:hover:border-sky-300 enabled:hover:text-sky-700 disabled:cursor-not-allowed disabled:opacity-50"
                            >
                              +
                            </button>
                          </div>

                          <div className="mt-3 text-sm text-slate-500">
                            Estimated monthly total
                          </div>
                          <div className="text-2xl font-semibold text-slate-900">
                            {toCurrency(total)} USD
                          </div>
                        </div>

                        <ul className="mt-5 space-y-3 text-sm text-slate-600">
                          {plan.features.map((feature) => (
                            <li
                              key={feature}
                              className="flex items-center gap-2"
                            >
                              <CheckIcon />
                              {feature}
                            </li>
                          ))}
                        </ul>

                        <button
                          type="button"
                          onClick={() => void handlePlanSelect(plan.key)}
                          disabled={buttonDisabled}
                          className="mt-6 rounded-xl bg-slate-900 px-4 py-3 text-sm font-semibold text-white transition enabled:hover:bg-slate-800 disabled:cursor-not-allowed disabled:bg-slate-300"
                        >
                          {isCurrentPlan
                            ? "Current Plan"
                            : `Select ${plan.name}`}
                        </button>
                      </div>
                    );
                  })}
                </div>

                <div className="mt-8 flex flex-wrap justify-center gap-3">
                  <Button
                    onClick={() => void handlePreviewBeforeConfirm()}
                    disabled={
                      mode === "seats" ? !canSubmitSeatMode : !canSubmitPlanMode
                    }
                  >
                    {mode === "seats" ? "Update Seats" : "Confirm Plan Change"}
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => navigate("/settings/pricing-plans")}
                  >
                    Back
                  </Button>
                </div>

                {previewData && (
                  <div className="mt-4 rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs text-slate-600">
                    Preview received. Charges shown above will be applied only
                    after confirmation.
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </div>

      <Dialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {mode === "seats" ? "Confirm Seat Update" : "Confirm Plan Change"}
            </DialogTitle>
            <DialogDescription>
              {previewMessage ??
                "A billing preview was generated for this change."}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmOpen(false)}>
              Cancel
            </Button>
            <Button onClick={() => void handleConfirm()} disabled={submitting}>
              {submitting ? "Applying..." : "Apply Change"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
