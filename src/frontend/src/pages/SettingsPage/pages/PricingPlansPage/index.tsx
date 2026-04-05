import { useAuth } from "@clerk/clerk-react";
import { useEffect, useMemo, useState } from "react";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import ForwardedIconComponent from "@/components/common/genericIconComponent";
import Loading from "@/components/ui/loading";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import planConfigData from "../../../../../public/plan_config.json";

type BillingAccessResponse = {
  has_access?: boolean;
  subscription_status?: string | null;
  subscription_plan_key?: string | null;
  paddle_subscription_id?: string | null;
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
      <p
        className="mt-1 text-xl font-semibold"
        data-testid="selected_pricing_plan"
      >
        {selectedPlan}
      </p>
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
  const [loading, setLoading] = useState(true);
  const [billing, setBilling] = useState<BillingAccessResponse | null>(null);

  useEffect(() => {
    if (!IS_CLERK_AUTH) {
      setLoading(false);
      return;
    }

    let mounted = true;

    const loadBilling = async () => {
      try {
        const token = await getToken();
        if (!token) {
          if (mounted) {
            setBilling(null);
            setLoading(false);
          }
          return;
        }

        const response = await api.get(getURL("BILLING_ACCESS"), {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (mounted) {
          setBilling(response.data ?? null);
        }
      } catch {
        if (mounted) {
          setBilling(null);
        }
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    void loadBilling();

    return () => {
      mounted = false;
    };
  }, [getToken]);

  return (
    <div className="flex h-full w-full flex-col gap-6">
      <div className="flex w-full items-start justify-between gap-6">
        <div className="flex flex-col">
          <h2
            className="flex items-center text-lg font-semibold tracking-tight"
            data-testid="settings_menu_header"
          >
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
        <SelectedPlan billing={billing} />
      )}
    </div>
  );
}
