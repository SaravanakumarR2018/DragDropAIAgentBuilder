import type { JSX, SVGProps } from "react";
import { useState } from "react";
import useAuthStore from "@/stores/authStore";
import { useLogout } from "@/clerk/auth";
import VisualWorkflow from "../../assets/VisualWorkflow.png";

function CheckIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" {...props}>
      <path
        d="M20.285 6.709a1 1 0 0 1 0 1.414l-9.192 9.192a1 1 0 0 1-1.414 0L3.715 11.55a1 1 0 0 1 1.414-1.415l5.136 5.136 8.485-8.485a1 1 0 0 1 1.535-.077z"
        fill="currentColor"
      />
    </svg>
  );
}

function PlayIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" {...props}>
      <path d="M8 5v14l11-7z" fill="currentColor" />
    </svg>
  );
}

function ArrowIcon(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" {...props}>
      <path d="M9 5l7 7-7 7" fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} />
    </svg>
  );
}

export default function Landing(): JSX.Element {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const { mutate: logout } = useLogout();

  const handleLogout = () => {
    logout();
  };

  const handleDashboardClick = () => {
    window.location.href = "/flows";
  };

  return (
    <div className="min-h-screen bg-neutral-950 text-white">
      <header className="sticky top-0 z-40 border-b border-white/10 bg-neutral-950/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4">
          <div className="flex items-center gap-3">
            <span className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-r from-teal-500 to-blue-500 text-base font-semibold">
              VA
            </span>
            <span className="text-sm font-semibold tracking-wide text-white/90 sm:text-base">
              Visual AI Agents Builder
            </span>
          </div>
          <nav className="hidden items-center gap-6 text-sm text-white/70 md:flex">
            <a href="#features" className="transition hover:text-white">
              Features
            </a>
            <a href="#how" className="transition hover:text-white">
              How it works
            </a>
            <a href="#enterprise" className="transition hover:text-white">
              Enterprise
            </a>
            <a href="#pricing" className="transition hover:text-white">
              Pricing
            </a>
          </nav>
          <div className="flex items-center gap-3 text-sm">
            <button
              className="inline-flex rounded-md border border-white/20 px-3 py-1.5 text-white/80 transition hover:bg-white/10 md:hidden"
              onClick={() => setIsMenuOpen((value) => !value)}
              aria-label="Toggle navigation menu"
            >
              <span className="sr-only">Menu</span>
              <div className="space-y-1">
                <span className="block h-0.5 w-5 bg-white" />
                <span className="block h-0.5 w-5 bg-white" />
                <span className="block h-0.5 w-5 bg-white" />
              </div>
            </button>
            {isAuthenticated ? (
              <>
                <button
                  onClick={handleLogout}
                  className="hidden rounded-md border border-white/20 px-3 py-1.5 text-white/80 transition hover:bg-white/10 md:inline-flex"
                >
                  Sign out
                </button>
                <button
                  onClick={handleDashboardClick}
                  className="inline-flex items-center gap-2 rounded-md bg-gradient-to-r from-teal-500 to-blue-500 px-4 py-2 text-sm font-semibold text-white transition hover:brightness-110"
                >
                  Dashboard
                  <ArrowIcon className="h-4 w-4" />
                </button>
              </>
            ) : (
              <>
                <a
                  href="#demo"
                  className="hidden rounded-md border border-white/20 px-3 py-1.5 text-white/80 transition hover:bg-white/10 md:inline-flex"
                >
                  Book a demo
                </a>
                <a
                  href="/login"
                  className="inline-flex rounded-md bg-white px-4 py-2 text-sm font-semibold text-neutral-900 transition hover:opacity-90"
                >
                  Log in
                </a>
              </>
            )}
          </div>
        </div>
        {isMenuOpen && (
          <div className="md:hidden">
            <div className="mx-4 mb-3 rounded-lg border border-white/15 bg-neutral-900/95 p-4 text-sm text-white/80 shadow-lg">
              <nav className="flex flex-col gap-3">
                {[
                  ["#features", "Features"],
                  ["#how", "How it works"],
                  ["#enterprise", "Enterprise"],
                  ["#pricing", "Pricing"],
                ].map(([href, label]) => (
                  <a
                    key={href}
                    href={href}
                    onClick={() => setIsMenuOpen(false)}
                    className="rounded-md px-2 py-1 transition hover:bg-white/10"
                  >
                    {label}
                  </a>
                ))}
              </nav>
            </div>
          </div>
        )}
      </header>

      <main className="mx-auto flex max-w-6xl flex-col gap-16 px-4 py-14 lg:flex-row lg:items-center">
        <section className="flex-1 space-y-6">
          <p className="text-xs font-semibold uppercase tracking-widest text-teal-300/80">
            Powered by Langflow & enterprise security
          </p>
          <h1 className="text-4xl font-semibold tracking-tight sm:text-5xl" data-testid="hero-headline">
            Build AI agents in minutes.
            <span className="block text-3xl text-white/70 sm:text-4xl">Drag, drop & deploy securely.</span>
          </h1>
          <p className="max-w-xl text-sm text-white/70 sm:text-base" data-testid="hero-subcopy">
            Visual AI Agents Builder gives teams a focused workspace to design, test, and ship secure Langflow deployments
            without writing boilerplate. Connect components, manage data policies, and publish confidently.
          </p>
          <div className="flex flex-wrap items-center gap-3">
            <a
              href="#demo"
              className="inline-flex items-center justify-center rounded-md bg-white px-5 py-2.5 text-sm font-semibold text-neutral-900 shadow-sm transition hover:opacity-90"
              data-testid="cta-demo"
            >
              Book a demo
            </a>
            <a
              href="#video"
              className="inline-flex items-center gap-2 rounded-md border border-white/15 px-5 py-2.5 text-sm text-white/90 transition hover:bg-white/10"
              data-testid="cta-video"
            >
              <PlayIcon className="h-4 w-4" />
              Watch the demo
            </a>
          </div>
          <ul className="grid max-w-md gap-2 text-sm text-white/60">
            {["Visual drag-and-drop flows", "Deploy as API or MCP tools", "Workspace isolation & SSO"].map((item) => (
              <li key={item} className="flex items-center gap-2">
                <CheckIcon className="h-4 w-4" />
                {item}
              </li>
            ))}
          </ul>
        </section>
        <section className="flex-1">
          <div className="rounded-xl border border-white/10 bg-neutral-900/70 p-4 shadow-lg shadow-black/30">
            <img
              src={VisualWorkflow}
              alt="Visual workflow builder screenshot"
              loading="lazy"
              className="h-auto w-full rounded-lg border border-white/5 object-cover"
            />
          </div>
        </section>
      </main>

      <section id="features" className="mx-auto max-w-6xl px-4 pb-16">
        <h2 className="text-2xl font-semibold">Product highlights</h2>
        <div className="mt-6 grid gap-5 md:grid-cols-3">
          {[
            {
              title: "Visual flow builder",
              desc: "Design complex agent workflows with reusable components and no boilerplate.",
            },
            {
              title: "Broad AI stack support",
              desc: "Connect any major LLM, database, or vector store and deploy to your environment.",
            },
            {
              title: "Governance ready",
              desc: "Tenant isolation, audit logs, and policy controls are built into every workspace.",
            },
          ].map((feature) => (
            <div key={feature.title} className="rounded-lg border border-white/10 bg-neutral-900/70 p-5 text-sm text-white/75">
              <h3 className="text-base font-semibold text-white">{feature.title}</h3>
              <p className="mt-2 leading-relaxed">{feature.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="how" className="mx-auto max-w-6xl px-4 pb-16">
        <h2 className="text-2xl font-semibold">How teams use Visual AI Agents Builder</h2>
        <div className="mt-6 grid gap-5 md:grid-cols-3">
          {[
            {
              step: "Plan",
              desc: "Start from curated templates or assemble agents from scratch with drag-and-drop nodes.",
            },
            {
              step: "Validate",
              desc: "Test flows in a live playground, monitor behavior, and iterate quickly with real data.",
            },
            {
              step: "Launch",
              desc: "Deploy as APIs or MCP tools, wire in observability, and control access with SSO.",
            },
          ].map((stage) => (
            <div key={stage.step} className="rounded-lg border border-white/10 bg-neutral-900/70 p-5 text-sm text-white/75">
              <h3 className="text-base font-semibold text-white">{stage.step}</h3>
              <p className="mt-2 leading-relaxed">{stage.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="enterprise" className="mx-auto max-w-6xl px-4 pb-16">
        <div className="rounded-xl border border-white/10 bg-neutral-900/70 p-6 text-center">
          <h2 className="text-2xl font-semibold">Enterprise ready from day one</h2>
          <p className="mt-3 text-sm text-white/70">
            Single sign-on, tenant isolation, audit logging, and data residency controls keep sensitive projects safe.
          </p>
          <div className="mt-6 grid gap-4 text-sm text-white/75 md:grid-cols-3">
            {[
              "Granular roles and workspace-level permissions",
              "Detailed audit history for every flow change",
              "Deploy on your infrastructure or in our managed cloud",
            ].map((item) => (
              <div key={item} className="rounded-lg border border-white/10 bg-neutral-950/70 px-4 py-5">
                {item}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="video" className="mx-auto flex max-w-6xl flex-col gap-8 px-4 pb-20 lg:flex-row lg:items-center">
        <div className="flex-1 space-y-3 text-sm text-white/75">
          <h2 className="text-2xl font-semibold text-white">See it in action</h2>
          <p>
            Take a quick tour of how teams build and validate agents, plug into enterprise data, and ship secure
            deployments with built-in governance.
          </p>
          <ul className="space-y-2">
            {["Local or managed deployments", "Observability out of the box", "Policy & compliance workflows"].map((item) => (
              <li key={item} className="flex items-center gap-2">
                <CheckIcon className="h-4 w-4" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="flex-1">
          <div className="aspect-video w-full overflow-hidden rounded-xl border border-white/10 bg-neutral-900/70">
            <img
              src="/images/demo-walkthrough.png"
              alt="Demo video walkthrough"
              loading="lazy"
              className="h-full w-full object-cover"
            />
          </div>
        </div>
      </section>
    </div>
  );
}
