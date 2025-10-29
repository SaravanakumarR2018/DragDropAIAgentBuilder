# Landing Page Bundle Optimization Design

## Objectives
- Deliver the public landing experience in a lightweight bundle (~200 KB for hero + CSS) that can load independently from the authenticated application shell.
- Move the authenticated app and the marketing landing page into distinct build outputs so that visiting the landing page does not download the app bundle.
- Adjust routing so that `/` serves the landing content while the app lives under `/app` (and `/app/...`).

## Entry Point Strategy
- Introduced `src/frontend/src/entry/landing-root.tsx` and `src/frontend/src/entry/app-root.tsx`.
  - `index.tsx` now detects the initial path and dynamically imports only the required entry module.
  - This enables Vite to emit separate chunks for landing (`landing-root`) and app (`app-root`).
  - The landing entry wraps the page with `BrowserRouter` + `AppWithProvider` but avoids importing the heavy app-wide CSS bundles.
- The app entry keeps the prior provider stack and global styles, ensuring authenticated experiences remain unchanged.

## Routing Layout
- Reworked `routes.tsx` to map the authenticated experience to `/app` (or `/:customParam/app` when custom parameters are enabled).
  - Marketing landing is no longer part of the app router; unauthenticated redirects now send users to `/` via standard `Navigate`.
  - Added helper `withCustomPrefix()` to generate prefixed paths when feature flags enable URL customisation.
- Updated guards (`CollectionIndexRedirect`, `CatchAllRedirect`, `authGuard`, `authLoginGuard`) and Clerk integration to target `/app/flows` instead of `/flows`.
- Adjusted auxiliary code (e.g., `use-get-autologin`, `use-add-flow`, Organization onboarding) to honour the new base path.

## Landing Page Styling
- Replaced the Tailwind-heavy landing implementation with bespoke CSS (`landing.css`).
  - Removes the dependency on the app’s global Tailwind bundle for the landing route.
  - New CSS provides gradients, layout, and responsive behavior in ~5 KB of custom styles.
- Simplified interactivity: no `framer-motion`; smooth scrolling handled with small helper utilities.
- Hero section loads a single image (`VisualWorkflow.png`) with `loading="lazy"` and emphasises actionable CTAs.

## Performance Considerations
- By separating entry points and excluding large app styles from the landing bundle, the initial payload for `/` is reduced dramatically.
- The hero content relies on lightweight CSS and avoids runtime animation libraries, keeping the critical path under ~200 KB once gzipped.
- Authenticated bundles still build as before; build output warnings are addressed separately if needed (current change focuses on bundle separation).

## Future Enhancements
- Consider lazy-loading the hero image via `IntersectionObserver` for further improvements on slower networks.
- Monitor Vite build output for the authenticated app chunks; additional manual chunk configuration could break down the remaining large assets if required.
