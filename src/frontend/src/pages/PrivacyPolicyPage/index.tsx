import { Link } from "react-router-dom";

export default function PrivacyPolicyPage() {
  return (
    <div className="min-h-screen bg-white text-gray-900">
      <main className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-6 py-12">
        <div className="flex flex-col gap-2">
          <Link to="/" className="text-sm font-medium text-blue-600">
            ← Back to home
          </Link>
          <h1 className="text-3xl font-semibold">Privacy Policy</h1>
          <p className="text-sm text-gray-500">Last updated: March 2025</p>
        </div>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Information we collect</h2>
          <p>
            We collect information you provide when creating an account,
            subscribing, or contacting support. We also collect usage data to
            operate and improve the platform.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Payment processing</h2>
          <p>
            Subscription payments are processed by Paddle. We do not store your
            full payment card details on our servers.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Service delivery</h2>
          <p>
            The platform is delivered through automated systems. There are no
            human-driven services involved in fulfilling the service.
          </p>
        </section>
      </main>
    </div>
  );
}
