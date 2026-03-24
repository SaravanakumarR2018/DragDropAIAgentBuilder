import { useAuth } from "@clerk/clerk-react";
import { initializePaddle } from "@paddle/paddle-js";
import { Suspense, useCallback, useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import {api} from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import { LoadingPage } from "./pages/LoadingPage";
import router from "./routes";
import { useDarkStore } from "./stores/darkStore";

const PADDLE_ENVIRONMENT =
  import.meta.env.VITE_PADDLE_ENVIRONMENT === "staging"
    ? "sandbox"
    : "production";
const PADDLE_TOKEN = import.meta.env.VITE_PADDLE_CLIENT_KEY;

export default function App() {
  const dark = useDarkStore((state) => state.dark);
  const { getToken } = IS_CLERK_AUTH
    ? useAuth()
    : { getToken: async () => null };

  const fetchPaddleSubscription = useCallback(async () => {
    if (!IS_CLERK_AUTH) {
      console.warn("Skipping Paddle subscription lookup because Clerk auth is disabled");
      return;
    }

    try {
      const clerkToken = await getToken();

      if (!clerkToken) {
        console.warn("Unable to resolve Clerk token for Paddle subscription lookup");
        return;
      }

      const { data } = await api.get(getURL("GET_PADDLE_SUBSCRIPTION"), {
        headers: {
          Authorization: `Bearer ${clerkToken}`,
        },
      });

      console.log("Resolved Paddle subscription from backend:", data);
    } catch (error) {
      console.error("Failed to fetch Paddle subscription from backend", error);
    }
  }, [getToken]);

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
          void fetchPaddleSubscription();
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
  }, [fetchPaddleSubscription]);

  return (
    <Suspense fallback={<LoadingPage />}>
      <RouterProvider router={router} />
    </Suspense>
  );
}
