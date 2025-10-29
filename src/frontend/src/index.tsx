import { BASENAME } from "./customization/config-constants";

const rootElement = document.getElementById("root") as HTMLElement;

if (!rootElement) {
  throw new Error("Root element not found");
}

const path = window.location.pathname;
const normalizedPath = BASENAME && path.startsWith(BASENAME)
  ? path.slice(BASENAME.length) || "/"
  : path;
const isLandingRoute = normalizedPath === "/";

async function bootstrap() {
  if (isLandingRoute) {
    const { mountLanding } = await import("./entry/landing-root");
    mountLanding(rootElement);
  } else {
    const { mountApp } = await import("./entry/app-root");
    mountApp(rootElement);
  }
}

void bootstrap();
