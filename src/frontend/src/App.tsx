import { useAuth, useOrganization } from "@clerk/clerk-react";
import { initializePaddle } from "@paddle/paddle-js";
import { Suspense, useCallback, useEffect } from "react";
import { RouterProvider } from "react-router-dom";
import { IS_CLERK_AUTH } from "@/clerk/auth";
import { api } from "@/controllers/API/api";
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
  const { organization } = IS_CLERK_AUTH
    ? useOrganization()
    : { organization: undefined };
  const { getToken } = IS_CLERK_AUTH
    ? useAuth()
    : { getToken: async () => null };

  const fetchPaddleSubscription = useCallback(async () => {
    if (!IS_CLERK_AUTH) {
      console.warn(
        "Skipping Paddle subscription lookup because Clerk auth is disabled",
      );
      return;
    }

    try {
      const clerkToken = await getToken();

      if (!clerkToken) {
        console.warn(
          "Unable to resolve Clerk token for Paddle subscription lookup",
        );
        return;
      }

      await new Promise((resolve) => {
        setTimeout(resolve, 3000);
      });

      const { data } = await api.post(
        getURL("GET_PADDLE_SUBSCRIPTION"),
        undefined,
        {
          headers: {
            Authorization: `Bearer ${clerkToken}`,
          },
        },
      );

      console.log("Resolved Paddle subscription from backend:", data);

      for (let attempt = 0; attempt < 3; attempt += 1) {
        const refreshedToken = await getToken({
          skipCache: true,
          organizationId: organization?.id,
        });

        if (!refreshedToken) {
          console.warn(
            "Unable to resolve refreshed Clerk token for org access check",
          );
          break;
        }

        const accessResponse = await api.get(getURL("BILLING_ACCESS"), {
          headers: {
            Authorization: `Bearer ${refreshedToken}`,
          },
        });

        const hasAccess = accessResponse.data?.has_access === true;
        console.log("Resolved org access from backend:", accessResponse.data);

        if (hasAccess) {
          window.location.href = "/flows";
          return;
        }

        // Give backend webhooks/claims propagation a moment before retrying.
        await new Promise((resolve) => {
          setTimeout(resolve, 1200);
        });
      }
    } catch (error) {
      console.error("Failed to fetch Paddle subscription from backend", error);
    }
  }, [getToken, organization?.id]);

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

          console.log("Paddle checkout completed", {
            customerId,
            subscriptionId,
          });
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
