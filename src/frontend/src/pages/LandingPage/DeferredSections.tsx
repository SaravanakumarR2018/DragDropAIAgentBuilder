import type { JSX } from "react";

import { CheckIcon } from "./icons";

const FEATURE_CARDS = [
  {
    title: "Visual Flow Builder",
    desc: "Build and connect components, agents, memory, tools & prompts via drag-drop to design complex AI workflows without writing boilerplate code.",
  },
  {
    title: "Wide AI Stack Support",
    desc: "Use any leading LLM or vector database; support for custom components. Cloud or local deployment options including GPU acceleration.",
  },
  {
    title: "Real-Time Testing & Deployment",
    desc: "Test flows in real time using playground; deploy flows as APIs or MCP servers; version control and inference options.",
  },
] as const;

const HOW_IT_WORKS = [
  {
    step: "01",
    title: "Design Flow",
    desc: "Choose from prebuilt templates or start fresh: drag & drop components to build agents, tools, memory, and LLM calls.",
  },
  {
    step: "02",
    title: "Test & Tune",
    desc: "Use live playground; adjust prompts, test agents; monitor performance and debug before deploying live.",
  },
  {
    step: "03",
    title: "Deploy Securely",
    desc: "Deploy to enterprise cloud or on-prem; configure SSO, isolate data per-tenant; audit logs & compliance baked-in.",
  },
] as const;

const ENTERPRISE_FEATURES = [
  {
    title: "Organization Tenancies & RBAC",
    desc: "Multiple teams under your account; fine-grained permissions; keep workspaces separated by team or business unit.",
  },
  {
    title: "Single Sign-On (SSO) & Audit Logs",
    desc: "Integrate SSO with your identity provider, get logs & user activity tracked for compliance & security reviews.",
  },
  {
    title: "Data Isolation & Security by Design",
    desc: "Isolated data per tenant; encrypted at rest & in transit; cloud or on-prem options; compliance support (GDPR, etc.).",
  },
] as const;

const SOCIAL_PROOF = [
  { k: "80%+", v: "reduction in development time" },
  { k: "Hundreds", v: "of LLMs & vector DBs supported" },
  { k: "Enterprise Ready", v: "SSO · Tenancies · Data Isolation" },
] as const;

const PRICING_FEATURES = [
  "Unlimited public flows",
  "Team seats & organization tenancies",
  "Enterprise support & SLA",
] as const;

export default function DeferredSections(): JSX.Element {
  return (
    <>
      <section id="features" className="mx-auto max-w-7xl px-4 py-20">
        <div className="mb-8 flex items-center justify-between">
          <h2 className="text-2xl font-semibold">Features</h2>
        </div>
        <div className="grid gap-6 md:grid-cols-3">
          {FEATURE_CARDS.map((feature) => (
            <div
              key={feature.title}
              className="rounded-2xl border border-white/10 bg-[#0f1217] p-6"
            >
              <h3 className="text-lg font-semibold">{feature.title}</h3>
              <p className="mt-2 text-sm text-white/70">{feature.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section id="how" className="mx-auto max-w-7xl px-4 py-20">
        <div className="mb-8 flex items-center justify-between">
          <h2 className="text-2xl font-semibold">How it Works</h2>
          <a href="#docs" className="text-sm text-white/70 hover:text-white">
            Read the Docs →
          </a>
        </div>
        <div className="grid gap-6 md:grid-cols-3">
          {HOW_IT_WORKS.map((step) => (
            <div
              key={step.title}
              className="relative rounded-2xl border border-white/10 p-6"
            >
              <span className="absolute -top-3 left-6 rounded-full border border-white/15 bg-[#0f1217] px-3 py-1 text-xs text-white/70">
                {step.step}
              </span>
              <h3 className="mt-2 text-lg font-semibold">{step.title}</h3>
              <p className="mt-2 text-sm text-white/70">{step.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section
        id="enterprise"
        className="mx-auto max-w-7xl rounded-2xl border border-white/10 bg-[#0f1217] px-4 py-20"
      >
        <h2 className="text-center text-2xl font-semibold">
          Enterprise-grade Capabilities
        </h2>
        <p className="mx-auto mt-3 max-w-2xl text-center text-white/70">
          Everything you need for teams, security, compliance, and scale.
        </p>
        <div className="mt-8 grid gap-6 md:grid-cols-3">
          {ENTERPRISE_FEATURES.map((enterprise) => (
            <div
              key={enterprise.title}
              className="rounded-2xl border border-white/10 bg-[#0f1217] p-6"
            >
              <h3 className="text-lg font-semibold">{enterprise.title}</h3>
              <p className="mt-2 text-sm text-white/70">{enterprise.desc}</p>
            </div>
          ))}
        </div>
      </section>

      <section className="mx-auto max-w-7xl px-4 py-20">
        <div className="grid gap-6 rounded-2xl border border-white/10 bg-[#0f1217] p-8 md:grid-cols-3">
          {SOCIAL_PROOF.map((item) => (
            <div key={item.k} className="text-center">
              <div className="text-4xl font-semibold tracking-tight">
                {item.k}
              </div>
              <div className="mt-1 text-sm text-white/70">{item.v}</div>
            </div>
          ))}
        </div>
      </section>

      <section id="video" className="mx-auto max-w-7xl px-4 py-20">
        <div className="grid items-center gap-8 md:grid-cols-2">
          <div>
            <h2 className="text-2xl font-semibold">See it In Action</h2>
            <p className="mt-3 max-w-prose text-white/70">
              Watch our walkthrough of the visual flow builder, enterprise
              features, and how quickly you can build & deploy an AI agent.
            </p>
            <div className="mt-6 flex flex-wrap items-center gap-3 text-sm text-white/70">
              <div className="flex items-center gap-2">
                <CheckIcon className="h-4 w-4" />
                Local & Cloud Deployment
              </div>
              <div className="flex items-center gap-2">
                <CheckIcon className="h-4 w-4" />
                Observability & Logging
              </div>
              <div className="flex items-center gap-2">
                <CheckIcon className="h-4 w-4" />
                Compliance & Security Controls
              </div>
            </div>
          </div>
          <div className="aspect-video w-full overflow-hidden rounded-2xl border border-white/10 bg-[#0f1217]">
            <img
              src="/images/demo-walkthrough.png"
              alt="Demo video walkthrough"
              loading="lazy"
              decoding="async"
              className="h-full w-full object-cover"
            />
          </div>
        </div>
      </section>

      <section id="pricing" className="mx-auto max-w-7xl px-4 py-20">
        <div className="rounded-2xl border border-white/10 bg-[#0f1217] p-8">
          <div className="grid gap-10 md:grid-cols-2">
            <div>
              <h2 className="text-2xl font-semibold">
                Fair, Transparent Pricing
              </h2>
              <p className="mt-3 text-white/70">
                Free (for developers) plus paid plans for teams and enterprise
                with full security & support.
              </p>
              <ul className="mt-6 space-y-2 text-sm text-white/80">
                {PRICING_FEATURES.map((item) => (
                  <li key={item} className="flex items-center gap-2">
                    <CheckIcon className="h-4 w-4" />
                    {item}
                  </li>
                ))}
              </ul>
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-white/10 bg-[#0f1217] p-6">
                <div className="text-sm text-white/60">Starter</div>
                <div className="mt-2 text-3xl font-semibold">Free</div>
                <p className="mt-2 text-sm text-white/70">
                  For personal projects, hobbyists. All core features except
                  enterprise.
                </p>
                <a
                  href="#signup"
                  className="mt-4 inline-block rounded-lg bg-white px-4 py-2 text-sm font-semibold text-neutral-900"
                >
                  Get Started Free
                </a>
              </div>
              <div className="rounded-xl border border-white/10 bg-[#0f1217] p-6">
                <div className="text-sm text-white/60">Enterprise</div>
                <div className="mt-2 text-3xl font-semibold">Contact Us</div>
                <p className="mt-2 text-sm text-white/70">
                  Includes SSO, data isolation, custom deployment, dedicated
                  support & SLAs.
                </p>
                <a
                  href="#contact"
                  className="mt-4 inline-block rounded-lg border border-white/15 px-4 py-2 text-sm"
                >
                  Contact Sales
                </a>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section id="blog" className="mx-auto max-w-7xl px-4 py-14">
        <div className="mb-8 flex items-center justify-between">
          <h2 className="text-2xl font-semibold">Latest from the Blog</h2>
          <a
            href="#all-posts"
            className="text-sm text-white/70 hover:text-white"
          >
            View all →
          </a>
        </div>
        <div className="grid gap-6 md:grid-cols-3">
          {[1, 2, 3].map((item) => (
            <article
              key={item}
              className="rounded-2xl border border-white/10 bg-[#0f1217] p-5"
            >
              <div className="aspect-[16/9] w-full rounded-lg bg-white/5" />
              <h3 className="mt-4 text-lg font-semibold">
                Blog post title {item}
              </h3>
              <p className="mt-1 text-sm text-white/70">
                Insights, tutorials & best practices on AI workflows, agents,
                and security.
              </p>
              <a
                href="#"
                className="mt-4 inline-block text-sm text-white/80 hover:text-white"
              >
                Read more →
              </a>
            </article>
          ))}
        </div>
      </section>

      <footer className="border-t border-white/10">
        <div className="mx-auto grid max-w-7xl gap-10 px-4 py-12 md:grid-cols-4">
          <div>
            <div className="inline-flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-blue-500 to-teal-500 font-bold">
              VA
            </div>
            <p className="mt-3 max-w-xs text-sm text-white/70">
              Build, deploy and scale AI agents enterprise-securely, powered by
              Langflow.
            </p>
          </div>
          <div>
            <div className="text-sm font-semibold">Product</div>
            <ul className="mt-3 space-y-2 text-sm text-white/70">
              <li>
                <a href="#features">Features</a>
              </li>
              <li>
                <a href="#how">How it Works</a>
              </li>
              <li>
                <a href="#enterprise">Enterprise</a>
              </li>
            </ul>
          </div>
          <div>
            <div className="text-sm font-semibold">Support</div>
            <ul className="mt-3 space-y-2 text-sm text-white/70">
              <li>
                <a href="#docs">Docs</a>
              </li>
              <li>
                <a href="#blog">Blog</a>
              </li>
              <li>
                <a href="#contact">Contact</a>
              </li>
            </ul>
          </div>
          <div>
            <div className="text-sm font-semibold">Legal & Company</div>
            <ul className="mt-3 space-y-2 text-sm text-white/70">
              <li>
                <a href="#privacy">Privacy Policy</a>
              </li>
              <li>
                <a href="#terms">Terms of Service</a>
              </li>
              <li>
                <a href="#careers">Careers</a>
              </li>
            </ul>
          </div>
        </div>
        <div className="border-t border-white/10 py-6 text-center text-xs text-white/60">
          © {new Date().getFullYear()} Visual AI Agents Builder. All rights
          reserved.
        </div>
      </footer>
    </>
  );
}
