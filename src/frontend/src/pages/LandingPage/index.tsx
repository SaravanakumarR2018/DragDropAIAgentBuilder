import type { JSX } from "react";
import { useEffect, useMemo, useState } from "react";

import VisualWorkflow from "../../assets/VisualWorkflow.png";
import { useLogout } from "@/clerk/auth";
import useAuthStore from "@/stores/authStore";
import { useCustomNavigate } from "@/customization/hooks/use-custom-navigate";

interface NavItem {
  href: string;
  label: string;
}

const NAV_ITEMS: NavItem[] = [
  { href: "#features", label: "Features" },
  { href: "#how", label: "How it works" },
  { href: "#enterprise", label: "Enterprise" },
  { href: "#pricing", label: "Pricing" },
];

export default function Landing(): JSX.Element {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const autoLogin = useAuthStore((state) => state.autoLogin);
  const { mutate: logout } = useLogout();
  const navigate = useCustomNavigate();
  const contactEmail = "mailto:hello@langflow.org";

  useEffect(() => {
    document.body.classList.add("landing-body");
    return () => {
      document.body.classList.remove("landing-body");
    };
  }, []);

  const handleDashboardClick = () => {
    setIsMenuOpen(false);
    navigate("/app/flows");
  };

  const handleLoginClick = () => {
    setIsMenuOpen(false);
    navigate("/login");
  };

  const scrollToSection = (selector: string) => {
    const section = document.querySelector(selector);
    if (section) {
      section.scrollIntoView({ behavior: "smooth" });
    }
  };

  const handleSignOut = () => {
    setIsMenuOpen(false);
    logout();
  };

  const isUserAuthenticated = useMemo(
    () => isAuthenticated || autoLogin === true,
    [autoLogin, isAuthenticated],
  );

  return (
    <div className="landing-page">
      <header className="landing-header">
        <div className="landing-header__inner">
          <div className="landing-brand">
            <span className="landing-brand__logo" aria-hidden>
              VA
            </span>
            <span className="landing-brand__text-short">
              Visual AI Agents Builder
            </span>
          </div>

          <nav className="landing-nav" aria-label="Primary">
            {NAV_ITEMS.map((item) => (
              <a key={item.href} href={item.href}>
                {item.label}
              </a>
            ))}
          </nav>

          <div className="landing-actions">
            {isUserAuthenticated ? (
              <>
                <button
                  className="landing-button landing-button--ghost"
                  onClick={handleSignOut}
                  type="button"
                >
                  Sign out
                </button>
                <button
                  className="landing-button landing-button--primary"
                  onClick={handleDashboardClick}
                  type="button"
                >
                  Dashboard
                </button>
              </>
            ) : (
              <>
                <button
                  className="landing-button landing-button--ghost"
                  onClick={() => {
                    setIsMenuOpen(false);
                    scrollToSection("#pricing");
                  }}
                  type="button"
                >
                  Book a demo
                </button>
                <button
                  className="landing-button landing-button--primary"
                  onClick={handleLoginClick}
                  type="button"
                >
                  Log in
                </button>
              </>
            )}

            <button
              aria-expanded={isMenuOpen}
              aria-label="Toggle navigation"
              className="landing-menu-button"
              onClick={() => setIsMenuOpen((open) => !open)}
              type="button"
            >
              <span />
              <span />
              <span />
            </button>
          </div>
        </div>

            {isMenuOpen ? (
              <div className="landing-menu" role="dialog">
                {NAV_ITEMS.map((item) => (
                  <a
                    key={item.href}
                    href={item.href}
                    onClick={() => setIsMenuOpen(false)}
                  >
                    {item.label}
                  </a>
                ))}
                {isUserAuthenticated ? (
                  <button onClick={handleDashboardClick} type="button">
                    Open dashboard
                  </button>
                ) : (
                  <>
                    <button
                      onClick={() => {
                        scrollToSection("#pricing");
                        setIsMenuOpen(false);
                      }}
                      type="button"
                    >
                      Book a demo
                    </button>
                    <button onClick={handleLoginClick} type="button">
                      Log in
                    </button>
                  </>
                )}
              </div>
            ) : null}
          </header>

      <main className="landing-main">
        <section aria-labelledby="hero-heading" className="landing-hero">
          <div>
            <p className="landing-hero__eyebrow">AI orchestration platform</p>
            <h1 className="landing-hero__title" id="hero-heading">
              Launch reliable AI agents without touching backend code
            </h1>
            <p className="landing-hero__subtitle">
              Visual AI Agents Builder gives product teams a single canvas to
              prototype, test, and deploy agentic workflows with proper
              observability and enterprise controls.
            </p>
            <div className="landing-hero__actions">
              <button
                className="landing-button landing-button--primary"
                onClick={handleDashboardClick}
                type="button"
              >
                Start building
              </button>
              <button
                className="landing-button landing-button--ghost"
                onClick={() => navigate("#how")}
                type="button"
              >
                See how it works
              </button>
            </div>
          </div>

          <div className="landing-hero__visual" role="presentation">
            <img
              alt="Workflow canvas preview"
              loading="lazy"
              src={VisualWorkflow}
            />
          </div>
        </section>

        <section className="landing-section" id="features">
          <div className="landing-section__inner">
            <h2 className="landing-section__title">Ship faster with guardrails</h2>
            <div className="landing-grid">
              <article className="landing-card">
                <h3>Visual workflow studio</h3>
                <p>
                  Drag-and-drop nodes to design complex agent behaviour, reuse
                  snippets, and integrate external tools without wrestling with
                  SDKs.
                </p>
              </article>
              <article className="landing-card">
                <h3>Built-in evaluation</h3>
                <p>
                  Run batch or real-time evaluations, capture telemetry, and
                  compare prompts to keep quality high before you ship.
                </p>
              </article>
              <article className="landing-card">
                <h3>Team ready</h3>
                <p>
                  Workspace roles, SSO, and audit-friendly logging come out of
                  the box so enterprise security teams can sign off quickly.
                </p>
              </article>
            </div>
          </div>
        </section>

        <section className="landing-section" id="how">
          <div className="landing-section__inner landing-enterprise">
            <div>
              <h2 className="landing-section__title">How it works</h2>
              <ol className="landing-list">
                <li>
                  <span className="landing-icon">1</span>
                  Prototype agents using a real-time canvas and reusable node
                  library.
                </li>
                <li>
                  <span className="landing-icon">2</span>
                  Connect to your data sources and deploy serverless endpoints.
                </li>
                <li>
                  <span className="landing-icon">3</span>
                  Monitor runs, tune prompts, and iterate with automatic
                  versioning.
                </li>
              </ol>
            </div>
            <div className="landing-enterprise__cta">
              <h3>Launch-ready infrastructure</h3>
              <p>
                Every deployment ships with structured logging, rollback support,
                and circuit breakers so production launches stay calm.
              </p>
              <button
                className="landing-button landing-button--primary"
                onClick={handleDashboardClick}
                type="button"
              >
                Go to the builder
              </button>
            </div>
          </div>
        </section>

        <section className="landing-section" id="enterprise">
          <div className="landing-section__inner landing-enterprise">
            <div>
              <h2 className="landing-section__title">Enterprise ready from day one</h2>
              <ul className="landing-list">
                <li>
                  <span className="landing-icon">✓</span>
                  SOC 2 aligned controls and customer-managed keys.
                </li>
                <li>
                  <span className="landing-icon">✓</span>
                  Private networking with zero egress deployments.
                </li>
                <li>
                  <span className="landing-icon">✓</span>
                  Fine-grained permissioning and workspace isolation.
                </li>
              </ul>
            </div>
            <div className="landing-enterprise__cta">
              <h3>Talk with our team</h3>
              <p>
                Need advanced compliance, on-prem support, or bespoke onboarding?
                Schedule time with our engineers and we will tailor a plan for
                your security posture.
              </p>
              <button
                className="landing-button landing-button--ghost"
                onClick={() => {
                  window.location.href = contactEmail;
                }}
                type="button"
              >
                Contact sales
              </button>
            </div>
          </div>
        </section>

        <section className="landing-section" id="pricing">
          <div className="landing-section__inner landing-enterprise">
            <div>
              <h2 className="landing-section__title">Pricing</h2>
              <p>
                Start for free, upgrade when your agents go to production.
                Flexible usage-based plans keep costs aligned with value.
              </p>
            </div>
            <div className="landing-enterprise__cta">
              <button
                className="landing-button landing-button--primary"
                onClick={handleDashboardClick}
                type="button"
              >
                Explore plans in app
              </button>
              <button
                className="landing-button landing-button--ghost"
                onClick={() => {
                  window.location.href = contactEmail;
                }}
                type="button"
              >
                Request enterprise quote
              </button>
            </div>
          </div>
        </section>
      </main>

      <footer className="landing-footer">
        © {new Date().getFullYear()} Visual AI Agents Builder. All rights
        reserved.
      </footer>
    </div>
  );
}
