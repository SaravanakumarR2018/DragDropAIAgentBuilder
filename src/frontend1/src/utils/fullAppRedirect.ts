const HTTP_PATTERN = /^https?:\/\//i;
const DEFAULT_PATH = "/flows";

const ensureLeadingSlash = (value: string) =>
  value.startsWith("/") ? value : `/${value}`;

const stripTrailingSlash = (value: string) =>
  value !== "/" ? value.replace(/\/+$/, "") : value;

const splitLocation = (value?: string) => {
  if (!value) {
    return { pathname: "", search: "", hash: "" };
  }

  let working = value.trim();
  if (!working) {
    return { pathname: "", search: "", hash: "" };
  }

  const hashIndex = working.indexOf("#");
  let hash = "";
  if (hashIndex >= 0) {
    hash = working.slice(hashIndex);
    working = working.slice(0, hashIndex);
  }

  const searchIndex = working.indexOf("?");
  let search = "";
  if (searchIndex >= 0) {
    search = working.slice(searchIndex);
    working = working.slice(0, searchIndex);
  }

  return { pathname: working, search, hash };
};

const normalizeBasePath = (value?: string) => {
  if (!value) return "";
  if (HTTP_PATTERN.test(value)) {
    return value.trim();
  }

  const trimmed = value.trim();
  if (!trimmed || trimmed === "/") {
    return trimmed === "/" ? "/" : "";
  }

  return stripTrailingSlash(ensureLeadingSlash(trimmed.replace(/^\/+/, "")));
};

const normalizeRelativePath = (value: string) => {
  if (!value) return "";
  const trimmed = value.trim();
  if (!trimmed) return "";
  return stripTrailingSlash(ensureLeadingSlash(trimmed.replace(/^\/+/, "")));
};

const combinePathSegments = (basePath: string, override: string) => {
  if (!override) {
    return basePath || DEFAULT_PATH;
  }

  if (HTTP_PATTERN.test(override)) {
    return override.trim();
  }

  const { pathname, search, hash } = splitLocation(override);

  if (!pathname) {
    const fallback = basePath || DEFAULT_PATH;
    return `${fallback}${search}${hash}`;
  }

  const normalizedOverride = normalizeRelativePath(pathname);
  if (!normalizedOverride) {
    const fallback = basePath || DEFAULT_PATH;
    return `${fallback}${search}${hash}`;
  }

  const normalizedBase = basePath && basePath !== "/" ? basePath : "";
  const pathResult = `${normalizedBase}${normalizedOverride}` || DEFAULT_PATH;
  return `${pathResult}${search}${hash}`;
};

const resolveWithAbsoluteBase = (baseUrl: string, override?: string) => {
  if (!override) return baseUrl;
  const trimmed = override.trim();
  if (!trimmed) return baseUrl;
  if (HTTP_PATTERN.test(trimmed)) return trimmed;

  try {
    const url = new URL(baseUrl);
    const { pathname, search, hash } = splitLocation(trimmed);

    if (search) {
      url.search = search;
    }
    if (hash) {
      url.hash = hash;
    }

    if (pathname) {
      const normalizedBase = stripTrailingSlash(url.pathname || "/");
      const normalizedOverride = normalizeRelativePath(pathname);
      const basePrefix = normalizedBase === "/" ? "" : normalizedBase;

      url.pathname = `${basePrefix}${normalizedOverride}` || DEFAULT_PATH;
    }

    return url.toString();
  } catch {
    return combinePathSegments("", override);
  }
};

const buildAbsoluteUrl = (target: string, origin: string) => {
  try {
    return new URL(target, origin).toString();
  } catch {
    return target;
  }
};

export const buildFullAppUrl = (overridePath?: string) => {
  const rawBase = import.meta.env.VITE_FULL_APP_BASE_PATH?.trim();
  const originOverride = import.meta.env.VITE_FULL_APP_ORIGIN?.trim();

  if (rawBase && HTTP_PATTERN.test(rawBase)) {
    return resolveWithAbsoluteBase(rawBase, overridePath);
  }

  const normalizedBase = normalizeBasePath(rawBase);
  const combined = combinePathSegments(normalizedBase, overridePath ?? "");

  if (originOverride && HTTP_PATTERN.test(originOverride)) {
    return buildAbsoluteUrl(combined, originOverride);
  }

  return combined;
};

export const handOffToFullApp = (overridePath?: string) => {
  if (typeof window === "undefined") return;

  const target = buildFullAppUrl(overridePath);
  const absoluteTarget = HTTP_PATTERN.test(target)
    ? target
    : buildAbsoluteUrl(target, window.location.origin);

  window.location.replace(target);
};
