import { Link } from "react-router-dom";
import logoicon from "../../assets/visualailogo.png";

export default function PrivacyPolicyPage() {
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
          <Link to="/" className="text-sm text-white/70 hover:text-white">
            Back to home
          </Link>
        </div>
      </header>

      <main className="mx-auto flex w-full max-w-3xl flex-col gap-6 px-6 py-12">
        <div className="flex flex-col gap-2">
          <h1 className="text-3xl font-semibold">Privacy Policy</h1>
          <p className="text-sm text-white/60">Last updated: March 2025</p>
        </div>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Information we collect</h2>
          <p className="text-white/80">
            Visual AI Agents Builder collects information you provide when
            creating an account, subscribing, or contacting support. We also
            collect usage data to operate and improve the platform.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Payment processing</h2>
          <p className="text-white/80">
            Subscription payments are processed by Paddle. We do not store your
            full payment card details on our servers.
          </p>
        </section>

        <section className="flex flex-col gap-3">
          <h2 className="text-xl font-semibold">Service delivery</h2>
          <p className="text-white/80">
            The platform is delivered through automated systems. There are no
            human-driven services involved in fulfilling the service.
          </p>
        </section>
      </main>
    </div>
  );
}
