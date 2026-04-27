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
const PADDLE_STATUS_STORAGE_KEY = "paddle_checkout_status";
const PADDLE_TRANSACTION_ID_STORAGE_KEY = "paddle_checkout_transaction_id";
const PADDLE_CHECKOUT_ORG_ID_STORAGE_KEY = "paddle_checkout_org_id";

function closePaddleCheckoutModal() {
  try {
    const paddle = (window as any)?.Paddle;
    if (paddle?.Checkout?.close) {
      paddle.Checkout.close();
      console.log("Closed Paddle checkout modal before subscription sync");
    }
  } catch (error) {
    console.warn("Unable to close Paddle checkout modal", error);
  }
}

function publishCheckoutStatus(
  status: "idle" | "processing" | "success" | "failed",
  transactionId?: string | null,
  organizationId?: string | null,
) {
  window.sessionStorage.setItem(PADDLE_STATUS_STORAGE_KEY, status);

  if (transactionId) {
    window.sessionStorage.setItem(PADDLE_TRANSACTION_ID_STORAGE_KEY, transactionId);
  } else {
    window.sessionStorage.removeItem(PADDLE_TRANSACTION_ID_STORAGE_KEY);
  }

  if (organizationId) {
    window.sessionStorage.setItem(PADDLE_CHECKOUT_ORG_ID_STORAGE_KEY, organizationId);
  } else {
    window.sessionStorage.removeItem(PADDLE_CHECKOUT_ORG_ID_STORAGE_KEY);
  }

  window.dispatchEvent(
    new CustomEvent("paddle-checkout-status", {
      detail: {
        status,
        transactionId: transactionId ?? null,
        organizationId: organizationId ?? null,
      },
    }),
  );
}

export default function App() {
  const dark = useDarkStore((state) => state.dark);
  const { organization } = IS_CLERK_AUTH
    ? useOrganization()
    : { organization: undefined };
  const { getToken } = IS_CLERK_AUTH
    ? useAuth()
    : { getToken: async () => null };

  const fetchPaddleSubscription = useCallback(async (transactionId?: string) => {
    if (!IS_CLERK_AUTH) {
      console.warn(
        "Skipping Paddle subscription lookup because Clerk auth is disabled",
      );
      publishCheckoutStatus("failed", transactionId ?? null, organization?.id ?? null);
      return;
    }

    try {
      const clerkToken = await getToken();

      if (!clerkToken) {
        console.warn(
          "Unable to resolve Clerk token for Paddle subscription lookup",
        );
        publishCheckoutStatus("failed", transactionId ?? null, organization?.id ?? null);
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

      const fallbackTransactionId =
        (data as any)?.transaction_id ??
        (data as any)?.transactionId ??
        transactionId ??
        null;

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
          publishCheckoutStatus(
            "success",
            fallbackTransactionId,
            organization?.id ?? null,
          );
          return;
        }

        // Give backend webhooks/claims propagation a moment before retrying.
        await new Promise((resolve) => {
          setTimeout(resolve, 1200);
        });
      }

      publishCheckoutStatus(
        "failed",
        fallbackTransactionId,
        organization?.id ?? null,
      );
    } catch (error) {
      console.error("Failed to fetch Paddle subscription from backend", error);
      publishCheckoutStatus("failed", transactionId ?? null, organization?.id ?? null);
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
          const transactionId =
            (event.data as any)?.transaction_id ??
            (event.data as any)?.transactionId ??
            (event.data as any)?.id ??
            null;
          const customerId = (event.data as any)?.customer?.id;
          const subscriptionId = (event.data as any)?.subscription?.id;

          console.log("Paddle checkout completed", {
            transactionId,
            customerId,
            subscriptionId,
          });
          publishCheckoutStatus(
            "processing",
            transactionId,
            organization?.id ?? null,
          );
          closePaddleCheckoutModal();
          void fetchPaddleSubscription(transactionId ?? undefined);
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
    <>
      <Suspense fallback={<LoadingPage />}>
        <RouterProvider router={router} />
      </Suspense>
    </>
  );
}
