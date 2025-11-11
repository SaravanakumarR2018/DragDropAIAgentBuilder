const HTTP_PATTERN = /^https?:\/\//i;
const DEFAULT_PATH = "/flows";

const normalizePath = (path: string) => {
  if (!path) return DEFAULT_PATH;
  return path.startsWith("/") ? path : `/${path}`;
};

const buildAbsoluteUrl = (target: string, origin: string) => {
  try {
    return new URL(target, origin).toString();
  } catch {
    return target;
  }
};

export const buildFullAppUrl = (overridePath?: string) => {
  const configured = import.meta.env.VITE_FULL_APP_BASE_PATH?.trim();
  const originOverride = import.meta.env.VITE_FULL_APP_ORIGIN?.trim();

  const desired = (overridePath?.trim() || configured || DEFAULT_PATH).trim();

  if (HTTP_PATTERN.test(desired)) {
    return desired;
  }

  const normalized = normalizePath(desired);
  if (originOverride && HTTP_PATTERN.test(originOverride)) {
    return buildAbsoluteUrl(normalized, originOverride);
  }

  return normalized;
};

export const handOffToFullApp = (overridePath?: string) => {
  if (typeof window === "undefined") return;

  const target = buildFullAppUrl(overridePath);
  const absoluteTarget = HTTP_PATTERN.test(target)
    ? target
    : buildAbsoluteUrl(target, window.location.origin);

  if (absoluteTarget === window.location.href) {
    return;
  }

  window.location.replace(target);
};
