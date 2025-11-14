import { Suspense, useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { LoadingPage } from "../src/pages/LoadingPage";
import { useDarkStore } from "../src/stores/darkStore";
import router from "./routes";

export default function ShellApp() {
  const dark = useDarkStore((state) => state.dark);

  useEffect(() => {
    const body = document.getElementById("body");
    if (!body) return;
    if (dark) {
      body.classList.add("dark");
    } else {
      body.classList.remove("dark");
    }
  }, [dark]);

  return (
    <Suspense fallback={<LoadingPage />}>
      <RouterProvider router={router} />
    </Suspense>
  );
}
