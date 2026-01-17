import { Link } from "react-router-dom";
import logoicon from "../../assets/visualailogo.png";

export default function RefundPolicyPage() {
  return (
    <div className="min-h-screen bg-[#0f1217] text-white">
      <div className="pointer-events-none fixed inset-0 -z-10">
        <div className="absolute -top-24 -left-24 h-72 w-72 rounded-full bg-gradient-to-br from-teal-500 to-blue-500/20 blur-3xl" />
        <div className="absolute -bottom-24 -right-24 h-72 w-72 rounded-full bg-gradient-to-br from-purple-500 to-pink-500/20 blur-3xl" />
      </div>

      <header className="sticky top-0 z-40 backdrop-blur supports-[backdrop-filter]:bg-neutral-900/60">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4">
          <Link to="/" className="flex items-center gap-2">
            <img src={logoicon} alt="Logo" className="h-8 w-8 object-contain drop-shadow-md" />
            <span className="whitespace-nowrap text-sm font-semibold tracking-wide text-white/90">
              Visual AI Agents Builder
            </span>
          </Link>
          <a href="/">Back to home</a>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-6 py-12">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-semibold">Refund Policy</h1>
          <p className="text-sm text-white/60">Last updated: March 2025</p>
        </div>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Subscriptions &amp; Billing</h2>
          <p className="text-white/80">
            Visual AI Agents Builder subscriptions are billed on a monthly recurring basis.
            Once a payment is successfully processed, your subscription will remain active
            until the end of the current billing period.
          </p>
          <p className="text-white/80">
            If you cancel your subscription, access will continue through the end of the
            current billing period, and no further charges will be made. Refund eligibility
            applies only to the initial subscription purchase, as outlined below.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">14-Day Cancellation Right (Initial Purchase Only)</h2>
          <p className="text-white/80">
            If you purchase Visual AI Agents Builder for personal use, you may cancel your
            initial subscription within 14 days of the original purchase date and receive a
            full refund.
          </p>
          <p className="text-white/80">
            Refunds requested within this 14-day period will be issued to the original
            payment method.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Digital Service Acknowledgement</h2>
          <p className="text-white/80">
            Visual AI Agents Builder is a digital service that is made available immediately
            upon purchase.
          </p>
          <p className="text-white/80">
            By creating an account, logging in, or otherwise accessing the platform, you
            acknowledge that the service has begun. Once access has started, you may cancel
            your subscription at any time through the billing portal; however, refunds,
            non-refunds, and service continuation are governed by the terms outlined in this
            policy. Service will continue until the end of the current billing period unless
            otherwise stated.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Renewals &amp; Ongoing Subscription Payments</h2>
          <p className="text-white/80">
            The 14-day cancellation right applies only to the first subscription purchase.
          </p>
          <p className="text-white/80">
            Subscription renewals are non-refundable. We do not provide refunds for partially
            used billing periods or for unused time after cancellation. Your service will
            remain active for the remainder of the billing period for which payment has been
            made.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Faulty or Unavailable Service</h2>
          <p className="text-white/80">
            This policy does not limit your statutory rights if the service is not as
            described, is not functioning, or is unavailable due to a verified technical
            issue. In such cases, a refund or other appropriate resolution may be provided.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Refund Abuse &amp; Charge Disputes</h2>
          <p className="text-white/80">
            We reserve the right to refuse refunds in cases of suspected fraud, abuse, or
            repeated refund requests. If you experience a billing issue, please contact us
            first so we can attempt to resolve it promptly.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">How to Request a Refund or Cancel a Subscription</h2>
          <p className="text-white/80">
            You can cancel your subscription at any time through the billing portal. Details
            regarding refund eligibility and service continuation through the end of the
            billing period will be displayed within the portal at the time of cancellation.
          </p>
        </section>
      </main>
    </div>
  );
}
