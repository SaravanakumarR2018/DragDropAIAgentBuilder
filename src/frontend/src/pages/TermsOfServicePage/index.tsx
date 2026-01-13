import { Link } from "react-router-dom";

export default function TermsOfServicePage() {
  return (
    <div className="min-h-screen bg-white text-gray-900">
      <main className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-6 py-12">
        <div className="flex flex-col gap-2">
          <Link to="/" className="text-sm font-medium text-blue-600">
            ← Back to home
          </Link>
          <h1 className="text-3xl font-semibold">Terms of Service</h1>
          <p className="text-sm text-gray-500">Last updated: March 2025</p>
        </div>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Service overview</h2>
          <p>
            Drag &amp; Drop AI Agent Builder provides an automated software
            platform. There are no human-driven services involved in this
            offering.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Subscriptions and billing</h2>
          <p>
            Plans are billed as monthly recurring subscriptions. Once a
            subscription payment is made, access is active for the remainder of
            that billing month.
          </p>
          <p>
            If you cancel your subscription, it remains active until the end of
            the current billing month and will not renew.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Refunds</h2>
          <p>All payments are final. We do not offer refunds.</p>
        </section>
      </main>
    </div>
  );
}
