// Shared constants for routing within the new landing page experience.
// Keep this in sync with the BrowserRouter basename so redirects land on the
// correct path regardless of which component triggers them.
const BASE_URL = import.meta.env.BASE_URL ?? "/";

export const LANDING_BASENAME =
  BASE_URL.length > 1 && BASE_URL.endsWith("/")
    ? BASE_URL.slice(0, -1)
    : BASE_URL;