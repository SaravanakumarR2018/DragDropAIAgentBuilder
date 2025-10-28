# Landing page fast-loading strategy

The landing page now renders the hero section immediately and delays heavier UI until the browser has time to download the remaining chunk.

## Key changes

- **Hero-first render:** The navigation, hero headline, and supporting call-to-action stay in the root component so they are part of the initial bundle. The hero image is marked with `fetchPriority="high"` and `decoding="async"` so the browser fetches it right away without blocking layout.
- **Deferred content loading:** Everything below the hero (feature lists, pricing, blog teaser, and footer) moved into `DeferredSections.tsx`. The landing page lazily imports this module inside a `Suspense` boundary after the browser becomes idle (`requestIdleCallback` with a `setTimeout` fallback). The hero renders instantly while the rest streams in.
- **Lean dependencies:** The page no longer depends on `framer-motion`. The animated arrow beside the dashboard button is now a lightweight CSS keyframe animation, and the mobile menu uses simple conditionals.
- **Media optimizations:** Non-critical images in deferred sections use `loading="lazy"` and `decoding="async"` so they download after the hero is visible.

## How to work with it

1. Update content in the hero section directly in `src/frontend/src/pages/LandingPage/index.tsx`.
2. Add or edit sections that can be deferred in `src/frontend/src/pages/LandingPage/DeferredSections.tsx`. Anything exported from this file loads after the hero by default.
3. If you add another critical-above-the-fold component, keep it in `index.tsx` so it stays in the first paint. Non-critical additions should go to the deferred module.
4. CSS rules specific to the hero (like the arrow animation) live in `src/frontend/src/App.css`. Tailwind utility classes still cover most styling.

This setup keeps the first render very small, letting visitors see the hero instantly while the rest of the page hydrates in the background.
