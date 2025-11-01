import { Suspense, useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { LoadingPage } from "./pages/LoadingPage";
import authRouter from "./auth-routes";
import { useDarkStore } from "./stores/darkStore";

export default function AuthApp() {
  const dark = useDarkStore((state) => state.dark);

  useEffect(() => {
    const body = document.getElementById("body");
    if (!body) return;

    if (!dark) {
      body.classList.remove("dark");
    } else {
      body.classList.add("dark");
    }
  }, [dark]);

  return (
    <Suspense fallback={<LoadingPage />}>
      <RouterProvider router={authRouter} />
    </Suspense>
  );
}
