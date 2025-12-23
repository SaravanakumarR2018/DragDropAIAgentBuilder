import React from "react";
import ReactDOM from "react-dom/client";
import { ClerkProvider } from "@clerk/clerk-react";
import { CookiesProvider } from "react-cookie";
import faviconUrl from "./new-assets/visualailogo.webp";
import App from "./App";
import "./index.css";

const clerkPublishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY || "";

if (!clerkPublishableKey) {
  console.warn("VITE_CLERK_PUBLISHABLE_KEY is not set. Clerk login will not function correctly.");
}

import React from "react";
import ReactDOM from "react-dom/client";
import { ClerkProvider } from "@clerk/clerk-react";
import { CookiesProvider } from "react-cookie";
import App from "./App";
import faviconUrl from "./new-assets/visualailogo.webp?inline";
import "./index.css";

const clerkPublishableKey = import.meta.env.VITE_CLERK_PUBLISHABLE_KEY || "";

if (!clerkPublishableKey) {
  console.warn("VITE_CLERK_PUBLISHABLE_KEY is not set. Clerk login will not function correctly.");
}

const setFavicon = (href: string) => {
  if (typeof document === "undefined") {
    return;
  }

  let favicon = document.querySelector<HTMLLinkElement>('link[rel~="icon"]');
  if (!favicon) {
    favicon = document.createElement("link");
    favicon.rel = "icon";
    document.head.appendChild(favicon);
  }

  favicon.href = href;
};

setFavicon(faviconUrl);

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <CookiesProvider>
      <ClerkProvider publishableKey={clerkPublishableKey}>
        <App />
      </ClerkProvider>
    </CookiesProvider>
  </React.StrictMode>,
);