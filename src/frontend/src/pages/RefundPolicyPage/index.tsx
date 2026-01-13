import { Link } from "react-router-dom";

export default function RefundPolicyPage() {
  return (
    <div className="min-h-screen bg-white text-gray-900">
      <main className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-6 py-12">
        <div className="flex flex-col gap-2">
          <Link to="/" className="text-sm font-medium text-blue-600">
            ← Back to home
          </Link>
          <h1 className="text-3xl font-semibold">Refund Policy</h1>
          <p className="text-sm text-gray-500">Last updated: March 2025</p>
        </div>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Monthly subscriptions</h2>
          <p>
            Subscriptions are billed on a monthly recurring basis. Once a
            payment is made, your subscription remains active until the end of
            that billing month.
          </p>
          <p>
            If you cancel, your subscription will stay active until the month
            ends and will not renew for the following month.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">No refunds</h2>
          <p>
            All payments are final. We do not provide refunds after a payment is
            made.
          </p>
        </section>
      </main>
    </div>
  );
}
