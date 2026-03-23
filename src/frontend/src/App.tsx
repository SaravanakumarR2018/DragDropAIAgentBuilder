import { Suspense, useEffect } from "react";
import { initializePaddle } from "@paddle/paddle-js";
import { api } from "./controllers/API/api";
import { getURL } from "./controllers/API/helpers/constants";
import { RouterProvider } from "react-router-dom";
import { LoadingPage } from "./pages/LoadingPage";
import router from "./routes";
import { useDarkStore } from "./stores/darkStore";


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

        if (event.name === "checkout.completed") {
          const customerId = (event.data as any)?.customer?.id;
          const subscriptionId = (event.data as any)?.subscription?.id;

          console.log("Paddle checkout completed", { customerId, subscriptionId });

          if (customerId) {
            api
              .get(getURL("GET_PADDLE_SUBSCRIPTION"),)
              .then(({ data }) => {
                console.log("Resolved Paddle subscription from backend:", data);
              })
              .catch((error) => {
                console.error(
                  "Failed to fetch Paddle subscription by customer ID",
                  error,
                );
              });
          } else {
            console.warn("Checkout completed without a Paddle customer id");
          }
        }

        if (event.name === "checkout.closed") {
          console.log("Checkout closed");
        }
      },
      checkout: {
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
