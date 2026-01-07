import { useMemo, useRef, useState } from "react";
import { Check, ShieldCheck } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { usePostCreateStripeCheckout } from "@/controllers/API/queries/billing/use-post-create-checkout";

const BillingPage = (): React.ReactElement => {
  const [activePlan, setActivePlan] = useState<"standard" | "pro" | null>(
    null,
  );
  const [enterpriseSubmitted, setEnterpriseSubmitted] = useState(false);
  const enterpriseRef = useRef<HTMLDivElement | null>(null);

  const { mutate: createCheckout, isPending } = usePostCreateStripeCheckout({
    onError: () => {
      setActivePlan(null);
    },
  });

  const plans = useMemo(
    () => [
      {
        id: "standard" as const,
        name: "Standard",
        price: "$20",
        cadence: "per month",
        description: "Great for small teams starting with Langflow.",
        limits: [
          "Up to 5 team seats",
          "Up to 200 active flows",
          "25k flow runs per month",
          "10 GB project storage",
          "Community support",
        ],
        cta: "Start Standard",
      },
      {
        id: "pro" as const,
        name: "Pro",
        price: "$50",
        cadence: "per month",
        description: "Scale production workloads with advanced controls.",
        limits: [
          "Up to 25 team seats",
          "Up to 2,000 active flows",
          "250k flow runs per month",
          "100 GB project storage",
          "Priority support & SLA",
        ],
        cta: "Go Pro",
        featured: true,
      },
      {
        id: "enterprise" as const,
        name: "Enterprise",
        price: "Contact us",
        cadence: "custom",
        description: "Enterprise-grade security, governance, and scale.",
        limits: [
          "Unlimited seats & flows",
          "Custom usage limits",
          "Dedicated infrastructure",
          "Security reviews & SSO",
          "Dedicated success team",
        ],
        cta: "Contact sales",
      },
    ],
    [],
  );

  const handleCheckout = (plan: "standard" | "pro") => {
    setActivePlan(plan);
    const baseUrl = window.location.origin;
    createCheckout(
      {
        plan,
        success_url: `${baseUrl}/flows`,
        cancel_url: `${baseUrl}/pricing`,
      },
      {
        onSuccess: (data) => {
          window.location.assign(data.url);
        },
      },
    );
  };

  const handleEnterpriseClick = () => {
    enterpriseRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const handleEnterpriseSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setEnterpriseSubmitted(true);
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="mx-auto flex w-full max-w-6xl flex-col gap-10 px-6 py-12">
        <div className="flex flex-col gap-3 text-center">
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-primary/10">
            <ShieldCheck className="h-6 w-6 text-primary" />
          </div>
          <h1 className="text-3xl font-semibold text-foreground">
            Trial access has ended
          </h1>
          <p className="text-base text-muted-foreground">
            Choose a plan to keep building with Langflow. Your workspace is ready
            once you subscribe.
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {plans.map((plan) => (
            <Card
              key={plan.id}
              className={`flex h-full flex-col ${
                plan.featured
                  ? "border-primary/60 shadow-lg shadow-primary/10"
                  : "border-border"
              }`}
            >
              <CardHeader className="space-y-2">
                <CardTitle className="text-xl">{plan.name}</CardTitle>
                <CardDescription>{plan.description}</CardDescription>
                <div className="flex items-baseline gap-2">
                  <span className="text-3xl font-semibold text-foreground">
                    {plan.price}
                  </span>
                  <span className="text-sm text-muted-foreground">
                    {plan.cadence}
                  </span>
                </div>
              </CardHeader>
              <CardContent className="flex-1">
                <ul className="space-y-3 text-sm text-muted-foreground">
                  {plan.limits.map((limit) => (
                    <li key={limit} className="flex items-start gap-2">
                      <Check className="mt-0.5 h-4 w-4 text-primary" />
                      <span>{limit}</span>
                    </li>
                  ))}
                </ul>
              </CardContent>
              <CardFooter>
                {plan.id === "enterprise" ? (
                  <Button className="w-full" onClick={handleEnterpriseClick}>
                    {plan.cta}
                  </Button>
                ) : (
                  <Button
                    className="w-full"
                    onClick={() => handleCheckout(plan.id)}
                    disabled={isPending && activePlan === plan.id}
                  >
                    {isPending && activePlan === plan.id
                      ? "Redirecting..."
                      : plan.cta}
                  </Button>
                )}
              </CardFooter>
            </Card>
          ))}
        </div>

        <div
          ref={enterpriseRef}
          className="rounded-2xl border border-border bg-card p-8"
        >
          <div className="mb-6">
            <h2 className="text-2xl font-semibold text-foreground">
              Enterprise contact form
            </h2>
            <p className="text-sm text-muted-foreground">
              Share your requirements and our team will help you design an
              enterprise plan.
            </p>
          </div>
          {enterpriseSubmitted ? (
            <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 text-sm text-foreground">
              Thank you! Our team will reach out to you shortly.
            </div>
          ) : (
            <form className="grid gap-4" onSubmit={handleEnterpriseSubmit}>
              <div className="grid gap-4 md:grid-cols-2">
                <Input placeholder="Full name" required />
                <Input type="email" placeholder="Work email" required />
              </div>
              <div className="grid gap-4 md:grid-cols-2">
                <Input placeholder="Company" required />
                <Input placeholder="Estimated team size" />
              </div>
              <Textarea
                placeholder="Tell us about your scale, compliance needs, and timeline."
                rows={4}
              />
              <div className="flex flex-col items-start gap-2 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-sm text-muted-foreground">
                  We typically respond within one business day.
                </span>
                <Button type="submit">Submit request</Button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};

export default BillingPage;
