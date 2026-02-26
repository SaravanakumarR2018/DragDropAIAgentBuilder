import { Suspense, useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { LoadingPage } from "./pages/LoadingPage";
import router from "./routes";
import { useDarkStore } from "./stores/darkStore";
import { initializePaddle } from "@paddle/paddle-js";

const PADDLE_ENVIRONMENT = (import.meta.env.VITE_PADDLE_ENVIRONMENT)=="staging" ? "sandbox" : "production";
const PADDLE_TOKEN = import.meta.env.VITE_PADDLE_CLIENT_KEY;
export default function App() {
  const dark = useDarkStore((state) => state.dark);

  // Dark mode + dynamic css import
  useEffect(() => {
    if (!dark) {
      document.getElementById("body")!.classList.remove("dark");
    } else {
      document.getElementById("body")!.classList.add("dark");
    }
    import("@xyflow/react/dist/style.css").catch(console.error);
  }, [dark]);

  useEffect(() => {
  initializePaddle({
    environment: PADDLE_ENVIRONMENT,
    token: PADDLE_TOKEN,
    eventCallback: (event) => {
      console.log("Paddle event:", event);

      // Checkout completed
      if (event.name === "checkout.completed") {
        const subscriptionId = (event.data as any)?.subscription?.id;
        console.log("Subscription ID:", subscriptionId);
         // navigate on success
      }

      // Checkout closed
      if (event.name === "checkout.closed") {
        console.log("Checkout closed");
      }
    },
    checkout: {
      // you can set global default settings here
      settings: {
        allowLogout: false,
      },
    },
  });
}, []);

  return (
    <Suspense fallback={<LoadingPage />}>
      <RouterProvider router={router} />
    </Suspense>
  );
}
