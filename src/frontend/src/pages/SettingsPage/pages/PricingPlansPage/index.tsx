import { useAuth } from "@clerk/clerk-react";
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
};

type PaddlePricesResponse = Record<string, string>;
type PlanStatus = "Active" | "Not Active";

type PlanDetails = {
  key: string;
  name: string;
  paddlePlanKey: string;
  monthlyPriceUsdCents: number;
};

const PLAN_NAME_BY_KEY = Object.fromEntries(
  (planConfigData.plans ?? []).map((plan) => [
    String(plan?.paddle?.plan_key ?? "").toLowerCase(),
    String(plan?.name ?? "").trim(),
  ]),
) as Record<string, string>;

const PRO_PLAN_KEY = (
  planConfigData.plans?.find((plan) => plan?.key === "pro")?.paddle?.plan_key ??
  "pro_pack_monthly"
).toLowerCase();

const STARTER_PLAN_KEY = (
  planConfigData.plans?.find((plan) => plan?.key === "starter")?.paddle
    ?.plan_key ?? "starter_pack_monthly"
).toLowerCase();

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
  const selectedPlanDetails = useMemo(() => {
    if (!billing?.has_access) return "Free";

    const planKey = (billing.subscription_plan_key ?? "").toLowerCase();
    const planName = PLAN_NAME_BY_KEY[planKey];
    if (planName) return planName;
    if (planKey) return formatPlanKey(planKey);

    const status = (billing.subscription_status ?? "").toLowerCase();
    return status === "trialing" ? "Paid (Trialing)" : "Paid";
  }, [billing]);

  const normalizedStatus = (billing?.subscription_status ?? "").toLowerCase();
  const isActiveStatus = ["active", "trialing", "past_due"].includes(
    normalizedStatus,
  );
  const currentStatus: PlanStatus =
    billing?.has_access && isActiveStatus ? "Active" : "Not Active";

  const monthlyAmount = useMemo(() => {
    const planKey = (billing?.subscription_plan_key ?? "").toLowerCase();
    const matchedPlan = AVAILABLE_PLANS.find(
      (plan) => plan.paddlePlanKey === planKey,
    );
    if (!matchedPlan) return "Not available";
    return `${formatCurrencyFromCents(matchedPlan.monthlyPriceUsdCents)} / month`;
  }, [billing?.subscription_plan_key]);

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

export default function PricingPlansPage() {
  const { getToken } = useAuth();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [billing, setBilling] = useState<BillingAccessResponse | null>(null);

  const [cancelModalOpen, setCancelModalOpen] = useState(false);
  const [cancelLoading, setCancelLoading] = useState(false);

  const [cancelError, setCancelError] = useState<string | null>(null);
  const [alreadyCancelled, setAlreadyCancelled] = useState(false);
  const [upgradeLoading, setUpgradeLoading] = useState(false);
  const [upgradeError, setUpgradeError] = useState<string | null>(null);
  const [upgradeSuccess, setUpgradeSuccess] = useState<string | null>(null);

  const [upgradeModalOpen, setUpgradeModalOpen] = useState(false);

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

  const currentPlanKey = (billing?.subscription_plan_key ?? "").toLowerCase();
  const isProPlan = currentPlanKey === PRO_PLAN_KEY;

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
        const token = await getToken();
        if (!token) {
          if (mounted) {
            setBilling(null);
            setLoading(false);
          }
          return;
        }

        const res = await api.get(getURL("BILLING_ACCESS"), {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (mounted) setBilling(res.data ?? null);
      } catch {
        if (mounted) setBilling(null);
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

  const handleChangeSubscription = async () => {
    setUpgradeLoading(true);
    setUpgradeError(null);
    setUpgradeSuccess(null);

    try {
      const token = await getToken();
      if (!token) throw new Error("Missing auth token");

      const { data: priceData } = await api.get<PaddlePricesResponse>(
        getURL("GET_PADDLE_PRICES"),
        { headers: { Authorization: `Bearer ${token}` } },
      );

      const targetPlanKey = isProPlan ? STARTER_PLAN_KEY : PRO_PLAN_KEY;
      const targetPriceId = priceData?.[targetPlanKey];

      if (!targetPriceId) {
        throw new Error("Unable to find target price ID");
      }

      await api.post(
        getURL("CHANGE_SUBSCRIPTION"),
        {
          price_id: targetPriceId,
          quantity: 1,
          is_upgrade: !isProPlan,
        },
        { headers: { Authorization: `Bearer ${token}` } },
      );

      const res = await api.get(getURL("BILLING_ACCESS"), {
        headers: { Authorization: `Bearer ${token}` },
      });

      setBilling(res.data ?? null);
      setUpgradeSuccess(
        isProPlan
          ? "Plan change scheduled for your next billing cycle."
          : "Plan changed successfully.",
      );
    } catch (error: any) {
      const msg =
        error?.response?.data?.detail ??
        error?.message ??
        "Failed to change subscription.";
      setUpgradeError(String(msg));
    } finally {
      setUpgradeLoading(false);
    }
  };

  return (
    <div className="flex h-full w-full flex-col gap-6">
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

      {loading ? (
        <div className="flex h-full w-full items-center justify-center">
          <Loading />
        </div>
      ) : !IS_CLERK_AUTH ? (
        <div className="rounded-xl border bg-background p-4 text-sm text-muted-foreground">
          Pricing plans are only available when Clerk billing is enabled.
        </div>
      ) : (
        <div className="space-y-4">
          <SelectedPlan billing={billing} />

          {cancelError && (
            <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {cancelError}
            </div>
          )}

          {upgradeError && (
            <div className="rounded-xl border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
              {upgradeError}
            </div>
          )}

          {upgradeSuccess && (
            <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 text-sm text-emerald-700 dark:text-emerald-300">
              {upgradeSuccess}
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
              <Button
                onClick={() => setUpgradeModalOpen(true)}
                disabled={upgradeLoading}
              >
                {upgradeLoading ? "Processing..." : "Change Plan"}
              </Button>
              <Button variant="outline" onClick={() => navigate("/pricing")}>
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

          <Dialog open={upgradeModalOpen} onOpenChange={setUpgradeModalOpen}>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>Change Plan</DialogTitle>
                <DialogDescription>
                  Update your plan. Pricing adjustments will be applied based on
                  your current billing cycle.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <Button onClick={() => setUpgradeModalOpen(false)}>
                  Cancel
                </Button>
                <Button
                  onClick={async () => {
                    setUpgradeModalOpen(false);
                    await handleChangeSubscription();
                  }}
                  disabled={upgradeLoading}
                >
                  {upgradeLoading ? "Processing..." : "Confirm Plan Change"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
      )}
    </div>
  );
}
