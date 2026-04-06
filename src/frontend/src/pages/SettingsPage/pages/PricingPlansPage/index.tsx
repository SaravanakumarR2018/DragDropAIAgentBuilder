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
  cancel_scheduled?: boolean;
};

const PLAN_NAME_BY_KEY = Object.fromEntries(
  (planConfigData.plans ?? []).map((plan) => [
    String(plan?.paddle?.plan_key ?? "").toLowerCase(),
    String(plan?.name ?? "").trim(),
  ]),
) as Record<string, string>;

function formatPlanKey(planKey: string): string {
  return planKey
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

function SelectedPlan({ billing }: { billing: BillingAccessResponse | null }) {
  const selectedPlan = useMemo(() => {
    if (!billing?.has_access) return "Free";

    const planKey = (billing.subscription_plan_key ?? "").toLowerCase();
    const planName = PLAN_NAME_BY_KEY[planKey];
    if (planName) return planName;
    if (planKey) return formatPlanKey(planKey);

    const status = (billing.subscription_status ?? "").toLowerCase();
    return status === "trialing" ? "Paid (Trialing)" : "Paid";
  }, [billing]);

  return (
    <div className="rounded-xl border bg-background p-4">
      <p className="text-sm text-muted-foreground">Selected plan</p>
      <p className="mt-1 text-xl font-semibold">{selectedPlan}</p>
      <div className="mt-3 space-y-1 text-sm text-muted-foreground">
        <p>Subscription status: {billing?.subscription_status ?? "not available"}</p>
        <p>Subscription ID: {billing?.paddle_subscription_id ?? "not available"}</p>
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

  const formattedNextBillingDate = useMemo(() => {
    const nextDateRaw = billing?.next_billed_at ?? billing?.current_period_end;
    if (!nextDateRaw) return null;

    const d = new Date(nextDateRaw);
    if (Number.isNaN(d.getTime())) return null;

    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(d);
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
    !alreadyCancelled;

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
    if (isCancelScheduled || (isCancelledState && billing?.has_access !== false)) {
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