import type { JSX, SVGProps } from "react";
import { lazy, Suspense, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import { useLogout } from "@/clerk/auth";
import useAuthStore from "@/stores/authStore";

import VisualWorkflow from "../../assets/VisualWorkflow.png";
import { CheckIcon, PlayIcon } from "./icons";

const LazyDeferredSections = lazy(async () => import("./DeferredSections"));

type ExtendedWindow = Window &
  typeof globalThis & {
    requestIdleCallback?: (
      callback: IdleRequestCallback,
      options?: IdleRequestOptions,
    ) => number;
    cancelIdleCallback?: (handle: number) => void;
  };

function ArrowIcon({ className, ...props }: SVGProps<SVGSVGElement>) {
  return (
    <svg
      viewBox="0 0 24 24"
      aria-hidden="true"
      className={["landing-arrow", className].filter(Boolean).join(" ")}
      {...props}
    >
      <path
        d="M8.59 16.59 13.17 12 8.59 7.41 10 6l6 6-6 6-1.41-1.41z"
        fill="currentColor"
      />
    </svg>
  );
}

function DeferredSkeleton(): JSX.Element {
  return (
    <div className="mx-auto max-w-7xl px-4 py-20">
      <div className="h-48 rounded-2xl border border-white/10 bg-white/5" />
    </div>
  );
}

const NAV_LINKS = [
  { href: "#features", label: "Features" },
  { href: "#how", label: "How it Works" },
  { href: "#enterprise", label: "Enterprise" },
  { href: "#pricing", label: "Pricing" },
] as const;

export default function Landing(): JSX.Element {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [shouldRenderDeferred, setShouldRenderDeferred] = useState(false);

  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  const { mutate: logout } = useLogout();
  const navigate = useNavigate();

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    let cancelled = false;
    const showDeferred = () => {
      if (!cancelled) {
        setShouldRenderDeferred(true);
      }
    };

    const extendedWindow = window as ExtendedWindow;

    if (extendedWindow.requestIdleCallback) {
      const idleId = extendedWindow.requestIdleCallback(showDeferred);
      return () => {
        cancelled = true;
        if (extendedWindow.cancelIdleCallback) {
          extendedWindow.cancelIdleCallback(idleId);
        }
      };
    }

    const timeoutId = window.setTimeout(showDeferred, 0);

    return () => {
      cancelled = true;
      window.clearTimeout(timeoutId);
    };
  }, []);

  useEffect(() => {
    if (typeof document === "undefined") {
      return;
    }

    const { body } = document;
    const previousOverflow = body.style.overflow;

    if (isMenuOpen) {
      body.style.overflow = "hidden";
      return () => {
        body.style.overflow = previousOverflow;
      };
    }

    body.style.overflow = previousOverflow;

    return () => {
      body.style.overflow = previousOverflow;
    };
  }, [isMenuOpen]);

  const handleLogout = () => {
    logout();
  };

  const handleDashboardClick = () => {
    navigate("/flows");
  };

  const closeMenu = () => setIsMenuOpen(false);

  return (
    <div className="min-h-screen overflow-y-auto bg-[#0f1217] text-white">
      <div className="pointer-events-none fixed inset-0 -z-10">
        <div className="absolute -left-24 -top-24 h-72 w-72 rounded-full bg-gradient-to-br from-teal-500 to-blue-500/20 blur-3xl" />
        <div className="absolute -bottom-24 -right-24 h-72 w-72 rounded-full bg-gradient-to-br from-purple-500 to-pink-500/20 blur-3xl" />
      </div>

      <header className="sticky top-0 z-40 backdrop-blur supports-[backdrop-filter]:bg-neutral-900/60">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4">
          <div className="flex items-center gap-2">
            <span className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-blue-500 to-teal-500 font-bold">
              VA
            </span>
            <span className="whitespace-nowrap text-sm font-semibold tracking-wide text-white/90 md:hidden">
              Visual AI Agents Builder
            </span>
            <span className="hidden whitespace-nowrap text-sm font-semibold tracking-wide text-white/90 md:inline">
              Visual AI Agents Builder
            </span>
          </div>

          <nav className="hidden items-center gap-8 md:flex">
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                className="text-white/70 hover:text-white"
                href={link.href}
              >
                {link.label}
              </a>
            ))}
          </nav>

          <div className="flex items-center gap-3">
            <button
              type="button"
              className="rounded-lg p-2 hover:bg-white/10 md:hidden"
              aria-label={isMenuOpen ? "Close navigation" : "Open navigation"}
              aria-expanded={isMenuOpen}
              onClick={() => setIsMenuOpen((open) => !open)}
            >
              <div className="space-y-1">
                <span className="block h-0.5 w-6 bg-white" />
                <span className="block h-0.5 w-6 bg-white" />
                <span className="block h-0.5 w-6 bg-white" />
              </div>
            </button>

            {isAuthenticated ? (
              <>
                <button
                  onClick={handleLogout}
                  className="hidden rounded-xl bg-white px-4 py-2 text-sm font-semibold text-neutral-900 transition hover:opacity-90 md:inline-block"
                >
                  Sign Out
                </button>
                <button
                  onClick={handleDashboardClick}
                  className="flex items-center gap-2 whitespace-nowrap rounded-xl bg-gradient-to-r from-teal-500 to-blue-500 px-4 py-2 text-sm font-semibold text-white transition hover:opacity-90"
                >
                  Dashboard
                  <ArrowIcon className="h-4 w-4" />
                </button>
              </>
            ) : (
              <>
                <a
                  href="#demo"
                  className="hidden rounded-xl bg-white px-4 py-2 text-sm font-semibold text-neutral-900 transition hover:opacity-90 md:inline-block"
                >
                  Book a Demo
                </a>
                <a
                  href="/login"
                  className="whitespace-nowrap rounded-xl bg-white px-4 py-2 text-sm font-semibold text-neutral-900 transition hover:opacity-90"
                >
                  Log in
                </a>
              </>
            )}
          </div>
        </div>
      </header>

      {isMenuOpen ? (
        <div className="fixed inset-0 z-50 flex flex-col items-center justify-start bg-gradient-to-b from-[#0f1217] via-[#0f1217]/95 to-transparent px-6 pt-24 backdrop-blur-md">
          <button
            type="button"
            className="absolute right-4 top-4 rounded-lg p-2 hover:bg-white/10"
            onClick={closeMenu}
            aria-label="Close navigation"
          >
            ✕
          </button>
          <nav className="space-y-6 text-center text-base">
            {NAV_LINKS.map((link) => (
              <a
                key={link.href}
                className="block text-white/90 hover:text-white"
                href={link.href}
                onClick={closeMenu}
              >
                {link.label}
              </a>
            ))}
          </nav>
        </div>
      ) : null}

      <section className="relative mx-auto max-w-7xl px-4 pb-12 pt-20 sm:pt-28">
        <div className="grid items-center gap-10 md:grid-cols-2">
          <div>
            <p className="mb-4 inline-block rounded-full border border-white/10 px-3 py-1 text-xs text-white/70">
              Powered by Langflow + Enterprise Security
            </p>
            <h1
              className="text-3xl font-semibold tracking-tight sm:text-5xl"
              data-testid="hero-headline"
            >
              Build AI Agents in Minutes.
              <br />
              <span className="block bg-gradient-to-r from-teal-400 to-blue-400 bg-clip-text pb-1 text-transparent">
                Drag, Drop & Deploy Securely.
              </span>
            </h1>
            <p
              className="mt-5 max-w-xl text-white/70"
              data-testid="hero-subcopy"
            >
              Visual AI Agents Builder brings you a no-/low-code interface on
              top of Langflow, with enterprise-grade tenancies, SSO, data
              isolation, audit logs & security out-of-the-box.
            </p>
            <div className="mt-6 flex flex-wrap items-center gap-3">
              <a
                href="#demo"
                className="rounded-xl bg-white px-5 py-3 text-sm font-semibold text-neutral-900"
                data-testid="cta-demo"
              >
                Book a Demo
              </a>
              <a
                href="#video"
                className="flex items-center gap-2 rounded-xl border border-white/15 px-5 py-3 text-sm text-white/90 hover:bg-white/5"
                data-testid="cta-video"
              >
                <PlayIcon className="h-4 w-4" /> Watch the Demo
              </a>
            </div>
            <div className="mt-6 flex flex-wrap items-center gap-6 text-xs text-white/60">
              <div className="flex items-center gap-2">
                <CheckIcon className="h-4 w-4" />
                Visual drag-and-drop flows
              </div>
              <div className="flex items-center gap-2">
                <CheckIcon className="h-4 w-4" />
                Deploy as API / MCP tools
              </div>
            </div>
          </div>
          <div className="relative">
            <img
              src={VisualWorkflow}
              alt="Visual workflow builder screenshot"
              loading="eager"
              decoding="async"
              fetchPriority="high"
              className="h-auto w-full rounded-2xl border border-black/5 object-cover"
            />
            <div className="absolute -bottom-4 -right-4 hidden h-40 w-40 rounded-full bg-teal-500/20 blur-2xl md:block" />
          </div>
        </div>
      </section>

      {shouldRenderDeferred ? (
        <Suspense fallback={<DeferredSkeleton />}>
          <LazyDeferredSections />
        </Suspense>
      ) : null}
    </div>
  );
}
