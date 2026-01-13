import { Link } from "react-router-dom";
import logoicon from "../../assets/visualailogo.png";

export default function TermsOfServicePage() {
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
          <h1 className="text-3xl font-semibold">Terms of Service</h1>
          <p className="text-sm text-white/60">Last updated: March 2025</p>
        </div>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Service overview</h2>
          <p className="text-white/80">
            These Terms of Service apply to Visual AI Agents Builder (the
            "Service"). The Service provides an automated software platform.
            There are no human-driven services involved in this offering.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Subscriptions and billing</h2>
          <p className="text-white/80">
            Plans are billed as monthly recurring subscriptions. Once a
            subscription payment is made, access is active for the remainder of
            that billing month.
          </p>
          <p className="text-white/80">
            If you cancel your subscription, it remains active until the end of
            the current billing month and will not renew.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Refunds</h2>
          <p className="text-white/80">All payments are final. We do not offer refunds.</p>
        </section>
      </main>
    </div>
  );
}
