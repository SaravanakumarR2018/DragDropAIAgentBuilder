import { useEffect, useRef, useState } from "react";

const LOCAL_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "0.0.0.0",
  "::1",
]);

function getEnvironmentLabel(hostname: string | null | undefined): string | null {
  if (!hostname) {
    return null;
  }

  const normalizedHost = hostname.trim().toLowerCase();

  if (!normalizedHost) {
    return null;
  }

  if (
    LOCAL_HOSTNAMES.has(normalizedHost) ||
    normalizedHost.endsWith(".local") ||
    /^\d{1,3}(\.\d{1,3}){3}$/.test(normalizedHost)
  ) {
    return "DEV";
  }

  const domainSegments = normalizedHost.split(".").filter(Boolean);

  if (domainSegments.length <= 2) {
    return null;
  }

  const subdomainSegments = domainSegments.slice(0, domainSegments.length - 2).join(".");
  const tokens = subdomainSegments
    .split(/[-.]/)
    .map((segment) => segment.trim())
    .filter((segment) => segment.length > 0 && segment !== "www");

  if (tokens.length === 0) {
    return null;
  }

  for (const token of tokens) {
    if (token.includes("staging")) {
      return "STAGING";
    }

    if (token.includes("dev")) {
      return "DEV";
    }

    if (token.includes("preview")) {
      return "PREVIEW";
    }

    if (token.includes("test")) {
      return "TEST";
    }
  }

  return tokens[0].toUpperCase();
}

export function EnvironmentWatermark() {
  const [watermarkLabel, setWatermarkLabel] = useState<string | null>(null);
  const originalTitleRef = useRef<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined") {
      setWatermarkLabel(null);
      return;
    }

    const label = getEnvironmentLabel(window.location.hostname);
    setWatermarkLabel(label);

    if (!label || typeof document === "undefined") {
      return;
    }

    const currentTitle = document.title;
    const baseTitle = currentTitle.replace(/^\[[^\]]+\]\s*/, "").trim();
    originalTitleRef.current = baseTitle || currentTitle;

    document.title = `[${label}] ${originalTitleRef.current}`.trim();

    return () => {
      if (originalTitleRef.current !== null) {
        document.title = originalTitleRef.current;
      }
    };
  }, []);

  if (!watermarkLabel) {
    return null;
  }

  return (
    <div className="pointer-events-none fixed left-4 top-4 z-50 select-none">
      <div className="rounded-md bg-muted px-3 py-1 text-xs font-semibold uppercase tracking-widest text-muted-foreground opacity-80 shadow">
        {watermarkLabel}
      </div>
    </div>
  );
}

export { getEnvironmentLabel };
