import { useAuth } from "@clerk/clerk-react";
import { motion } from "framer-motion";
import { AlertCircle, CreditCard } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import ForwardedIconComponent from "@/components/common/genericIconComponent";
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
import planConfigData from "../../../../../public/plan_config.json";

type BillingAccessResponse = {
  has_access?: boolean;
  is_admin?: boolean;
  subscription_status?: string | null;
  subscription_plan_key?: string | null;
  paddle_subscription_id?: string | null;
  next_billed_at?: string | null;
  current_period_end?: string | null;
  current_period_start?: string | null;
  cancel_scheduled?: boolean;
  subscription_seats?: number | null;
  seats?: number | null;
  quantity?: number | null;
  current_price_plan_key?: string | null;
  scheduled_change_action?: string | null;
  scheduled_change_effective_at?: string | null;
  pending_plan_key?: string | null;
};

type PlanStatus = "Active" | "Not Active";

type PlanDetails = {
  key: string;
  name: string;
  paddlePlanKey: string;
  monthlyPriceUsdCents: number;
};

const ACTIVE_SUBSCRIPTION_STATUSES = new Set([
  "active",
  "trialing",
  "past_due",
]);

const PLAN_NAME_BY_KEY = Object.fromEntries(
  (planConfigData.plans ?? []).map((plan) => [
    String(plan?.paddle?.plan_key ?? "").toLowerCase(),
    String(plan?.name ?? "").trim(),
  ]),
) as Record<string, string>;

const AVAILABLE_PLANS: PlanDetails[] = (planConfigData.plans ?? []).map(
  (plan) => ({
    key: String(plan?.key ?? ""),
    name: String(plan?.name ?? "").trim(),
    paddlePlanKey: String(plan?.paddle?.plan_key ?? "").toLowerCase(),
    monthlyPriceUsdCents: Number(plan?.paddle?.monthly_price_usd_cents ?? 0),
  }),
);

function formatPlanKey(planKey: string): string {
  return planKey
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatDate(value?: string | null): string {
  if (!value) return "Not available";

  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Not available";

  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(
    date,
  );
}

function formatCurrencyFromCents(cents: number): string {
  return new Intl.NumberFormat(undefined, {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 2,
  }).format(cents / 100);
}

function SelectedPlan({ billing }: { billing: BillingAccessResponse | null }) {
  const effectivePlanKey = useMemo(() => {
    const currentPricePlanKey = (
      billing?.current_price_plan_key ?? ""
    ).toLowerCase();
    if (currentPricePlanKey) return currentPricePlanKey;
    return (billing?.subscription_plan_key ?? "").toLowerCase();
  }, [billing?.current_price_plan_key, billing?.subscription_plan_key]);

  const selectedPlanDetails = useMemo(() => {
    if (!billing?.has_access) return "Free";

    const planName = PLAN_NAME_BY_KEY[effectivePlanKey];
    if (planName) return planName;
    if (effectivePlanKey) return formatPlanKey(effectivePlanKey);

    const status = (billing.subscription_status ?? "").toLowerCase();
    return status === "trialing" ? "Paid (Trialing)" : "Paid";
  }, [billing, effectivePlanKey]);

  const normalizedStatus = (billing?.subscription_status ?? "").toLowerCase();
  const isActiveStatus = ["active", "trialing", "past_due"].includes(
    normalizedStatus,
  );
  const currentStatus: PlanStatus =
    billing?.has_access && isActiveStatus ? "Active" : "Not Active";

  const monthlyAmount = useMemo(() => {
    const matchedPlan = AVAILABLE_PLANS.find(
      (plan) => plan.paddlePlanKey === effectivePlanKey,
    );
    if (!matchedPlan) return "Not available";
    return `${formatCurrencyFromCents(matchedPlan.monthlyPriceUsdCents)} / month`;
  }, [effectivePlanKey]);

  const scheduledPlanLabel = useMemo(() => {
    const isPlanChangeScheduled =
      (billing?.scheduled_change_action ?? "").toLowerCase() === "update";
    const pendingPlanKey = (billing?.pending_plan_key ?? "").toLowerCase();
    if (!isPlanChangeScheduled || !pendingPlanKey) return null;
    if (pendingPlanKey === effectivePlanKey) return null;
    return PLAN_NAME_BY_KEY[pendingPlanKey] ?? formatPlanKey(pendingPlanKey);
  }, [
    billing?.pending_plan_key,
    billing?.scheduled_change_action,
    effectivePlanKey,
  ]);

  const seatCount = useMemo(() => {
    const firstAvailableSeatValue =
      billing?.subscription_seats ??
      billing?.seats ??
      billing?.quantity ??
      null;
    if (
      firstAvailableSeatValue === null ||
      firstAvailableSeatValue === undefined
    ) {
      return "Not available";
    }

    return String(firstAvailableSeatValue);
  }, [billing?.quantity, billing?.seats, billing?.subscription_seats]);

  return (
    <div className="rounded-xl border bg-background p-4">
      <p className="text-sm text-muted-foreground">Current plan details</p>
      <p className="mt-1 text-xl font-semibold">{selectedPlanDetails}</p>
      {scheduledPlanLabel && (
        <p className="mt-1 text-sm text-muted-foreground">
          Scheduled plan change: {scheduledPlanLabel}{" "}
          {billing?.scheduled_change_effective_at
            ? `on ${formatDate(billing.scheduled_change_effective_at)}`
            : "at your next billing date"}
        </p>
      )}
      <div className="mt-4 grid gap-3 text-sm sm:grid-cols-2">
        <div className="rounded-lg border bg-muted/20 p-3">
          <p className="text-xs text-muted-foreground">Plan Name</p>
          <p className="mt-1 font-medium">{selectedPlanDetails}</p>
        </div>
        <div className="rounded-lg border bg-muted/20 p-3">
          <p className="text-xs text-muted-foreground">Current Status</p>
          <p className="mt-1 font-medium">{currentStatus}</p>
        </div>
        <div className="rounded-lg border bg-muted/20 p-3">
          <p className="text-xs text-muted-foreground">Plan Start Date</p>
          <p className="mt-1 font-medium">
            {formatDate(billing?.current_period_start)}
          </p>
        </div>
        <div className="rounded-lg border bg-muted/20 p-3">
          <p className="text-xs text-muted-foreground">Plan End Date</p>
          <p className="mt-1 font-medium">
            {formatDate(billing?.next_billed_at ?? billing?.current_period_end)}
          </p>
        </div>
        <div className="rounded-lg border bg-muted/20 p-3 sm:col-span-2">
          <p className="text-xs text-muted-foreground">Amount per Month</p>
          <p className="mt-1 font-medium">{monthlyAmount}</p>
        </div>
        <div className="rounded-lg border bg-muted/20 p-3 sm:col-span-2">
          <p className="text-xs text-muted-foreground">Seats</p>
          <p className="mt-1 font-medium">{seatCount}</p>
        </div>
      </div>
      <div className="mt-3 space-y-1 text-sm text-muted-foreground">
        <p>
          Subscription status: {billing?.subscription_status ?? "not available"}
        </p>
        <p>
          Subscription ID: {billing?.paddle_subscription_id ?? "not available"}
        </p>
      </div>
    </div>
  );
}

function NoSubscriptionEmptyState() {
  return (
    <div className="flex min-h-[calc(100vh-12rem)] w-full items-center justify-center px-6 py-10">
      <motion.div
        initial={{ opacity: 0, scale: 0.96, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        transition={{ duration: 0.35, ease: "easeOut" }}
        className="w-full max-w-xl rounded-3xl border bg-background/95 p-10 text-center shadow-sm backdrop-blur"
      >
        <div className="mx-auto flex h-20 w-20 items-center justify-center rounded-full bg-primary/10 text-primary">
          <CreditCard className="h-10 w-10" strokeWidth={1.8} />
        </div>
        <h2 className="mt-6 text-2xl font-semibold tracking-tight">
          No Active Subscription
        </h2>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">
          Your organization does not have an active subscription. Please contact
          your admin to get access.
        </p>
        <Button className="mt-8" variant="outline" disabled>
          Contact Admin
        </Button>
      </motion.div>
    </div>
  );
}

export default function PricingPlansPage() {
  const { getToken } = useAuth();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [billing, setBilling] = useState<BillingAccessResponse | null>(null);
  const [billingError, setBillingError] = useState<string | null>(null);

  const [cancelModalOpen, setCancelModalOpen] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);

  const [cancelError, setCancelError] = useState<string | null>(null);
  const [alreadyCancelled, setAlreadyCancelled] = useState(false);
  const formattedNextBillingDate = useMemo(() => {
    const nextDateRaw = billing?.next_billed_at ?? billing?.current_period_end;
    if (!nextDateRaw) return null;

    const d = new Date(nextDateRaw);
    if (Number.isNaN(d.getTime())) return null;

    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(
      d,
    );
  }, [billing?.current_period_end, billing?.next_billed_at]);

  const accessEndsMessage = formattedNextBillingDate
    ? `until ${formattedNextBillingDate}`
    : "until the end of your current billing period";

  const normalizedStatus = (billing?.subscription_status ?? "").toLowerCase();

  const isCancelledState =
    normalizedStatus === "canceled" || normalizedStatus === "cancelled";

  const isCancelScheduled = Boolean(billing?.cancel_scheduled);

  const canCancelSubscription =
    Boolean(billing?.paddle_subscription_id) &&
    !isCancelledState &&
    !isCancelScheduled &&
    !alreadyCancelled &&
    Boolean(billing?.is_admin);

  const canChangeSubscription =
    Boolean(billing?.paddle_subscription_id) &&
    !isCancelledState &&
    !isCancelScheduled &&
    Boolean(billing?.is_admin);

  useEffect(() => {
    if (!IS_CLERK_AUTH) {
      setLoading(false);
      return;
    }

    let mounted = true;

    const load = async () => {
      try {
        setBillingError(null);
        const token = await getToken();
        if (!token) {
          if (mounted) {
            setBilling(null);
            setBillingError(
              "Unable to load billing access. Please sign in again.",
            );
            setLoading(false);
          }
          return;
        }

        const res = await api.get(getURL("BILLING_ACCESS"), {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (mounted) setBilling(res.data ?? null);
      } catch (error: any) {
        if (mounted) {
          setBilling(null);
          setBillingError(
            error?.response?.data?.detail ??
              error?.message ??
              "Failed to load billing details.",
          );
        }
      } finally {
        if (mounted) setLoading(false);
      }
    };

    void load();
    return () => {
      mounted = false;
    };
  }, [getToken]);

  useEffect(() => {
    if (
      isCancelScheduled ||
      (isCancelledState && billing?.has_access !== false)
    ) {
      setAlreadyCancelled(true);
    }

    if (alreadyCancelled) return;

    if (isCancelledState && billing?.has_access === false) {
      navigate("/pricing", { replace: true });
    }
  }, [
    alreadyCancelled,
    billing?.has_access,
    isCancelScheduled,
    isCancelledState,
    navigate,
  ]);

  const handleCancelSubscription = async () => {
    if (alreadyCancelled || isCancelScheduled) {
      setCancelError(
        `Subscription Cancelled Successfully. Access continues ${accessEndsMessage}.`,
      );
      setCancelModalOpen(false);
      return;
    }

    setCancelLoading(true);
    setCancelError(null);

    try {
      const token = await getToken();
      if (!token) throw new Error("Missing auth token");

      await api.post(
        getURL("CANCEL_PADDLE_SUBSCRIPTION"),
        { effective_from_immediately: false },
        { headers: { Authorization: `Bearer ${token}` } },
      );

      setAlreadyCancelled(true);
      setCancelModalOpen(false);

      const res = await api.get(getURL("BILLING_ACCESS"), {
        headers: { Authorization: `Bearer ${token}` },
      });

      setBilling(res.data ?? null);
    } catch (error: any) {
      const msg =
        error?.response?.data?.detail ??
        error?.message ??
        "Failed to cancel subscription.";

      if (String(msg).toLowerCase().includes("already")) {
        setAlreadyCancelled(true);
        setCancelError(
          `Subscription Cancelled Successfully. You still have access ${accessEndsMessage}.`,
        );
      } else {
        setCancelError(String(msg));
      }
    } finally {
      setCancelLoading(false);
    }
  };

  const isAdmin = Boolean(billing?.is_admin);
  const normalizedSubscriptionStatus = (
    billing?.subscription_status ?? ""
  ).toLowerCase();
  const hasActiveSubscription =
    billing?.has_access === true ||
    ACTIVE_SUBSCRIPTION_STATUSES.has(normalizedSubscriptionStatus);
  const showNoSubscriptionEmptyState =
    IS_CLERK_AUTH && !loading && !isAdmin && !hasActiveSubscription;

  return (
    <div className="flex h-full w-full flex-col gap-6">
      {loading ? (
        <div className="flex h-full min-h-[60vh] w-full items-center justify-center">
          <Loading />
        </div>
      ) : billingError ? (
        <div className="flex min-h-[60vh] w-full items-center justify-center px-4">
          <div className="w-full max-w-md rounded-2xl border border-destructive/30 bg-destructive/10 p-6 text-center">
            <AlertCircle className="mx-auto h-8 w-8 text-destructive" />
            <h2 className="mt-3 text-lg font-semibold text-foreground">
              Billing Unavailable
            </h2>
            <p className="mt-2 text-sm text-muted-foreground">{billingError}</p>
          </div>
        </div>
      ) : showNoSubscriptionEmptyState ? (
        <NoSubscriptionEmptyState />
      ) : !IS_CLERK_AUTH ? (
        <div className="rounded-xl border bg-background p-4 text-sm text-muted-foreground">
          Pricing plans are only available when Clerk billing is enabled.
        </div>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-col">
            <h2 className="flex items-center text-lg font-semibold tracking-tight">
              Pricing Plans
              <ForwardedIconComponent
                name="BadgeDollarSign"
                className="ml-2 h-5 w-5 text-primary"
              />
            </h2>
            <p className="text-sm text-muted-foreground">
              Review your current workspace plan and subscription status.
            </p>
          </div>

          <SelectedPlan billing={billing} />

          {cancelError && (
            <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {cancelError}
            </div>
          )}

          {alreadyCancelled && (
            <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-700 dark:text-amber-300">
              You already cancelled your subscription. You still have access{" "}
              {accessEndsMessage}.
            </div>
          )}

          {canCancelSubscription && (
            <Button
              variant="destructive"
              onClick={() => setCancelModalOpen(true)}
            >
              Cancel subscription
            </Button>
          )}

          {canChangeSubscription && (
            <div className="flex flex-wrap gap-2">
              <Button onClick={() => navigate("/change-plans?mode=plan")}>
                Change Plan
              </Button>
              <Button
                variant="outline"
                onClick={() => navigate("/change-plans?mode=seats")}
              >
                Change Seats
              </Button>
            </div>
          )}

          <Dialog open={cancelModalOpen} onOpenChange={setCancelModalOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Cancel subscription</DialogTitle>
                <DialogDescription>
                  You have access {accessEndsMessage}
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button onClick={() => setCancelModalOpen(false)}>
                  Keep subscription
                </Button>
                <Button
                  onClick={handleCancelSubscription}
                  disabled={cancelLoading}
                >
                  Confirm cancel
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      )}
    </div>
  );
}
