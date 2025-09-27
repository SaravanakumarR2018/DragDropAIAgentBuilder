// React-Flow styles are imported in FlowPage instead of globally, so that
// they aren't included in the landing bundle.

// Import application-wide styles (Tailwind base/components/utilities).
import "./App.css";
import { Suspense, useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { LoadingPage } from "./pages/LoadingPage";
import router from "./routes";
import { useDarkStore } from "./stores/darkStore";

export default function App() {
  const dark = useDarkStore((state) => state.dark);
  useEffect(() => {
    if (!dark) {
      document.getElementById("body")!.classList.remove("dark");
    } else {
      document.getElementById("body")!.classList.add("dark");
    }
  }, [dark]);
  return (
    <Suspense fallback={<LoadingPage />}>
      <RouterProvider router={router} />
    </Suspense>
  );
}
