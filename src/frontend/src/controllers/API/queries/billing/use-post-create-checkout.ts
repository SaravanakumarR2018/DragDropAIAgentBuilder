import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "@/types/api";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";
import { UseRequestProcessor } from "@/controllers/API/services/request-processor";

export type StripeCheckoutPayload = {
  plan: "standard" | "pro";
  success_url: string;
  cancel_url: string;
};

export type StripeCheckoutResponse = {
  url: string;
};

export const usePostCreateStripeCheckout: useMutationFunctionType<
  StripeCheckoutPayload,
  StripeCheckoutResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  const createCheckout = async (payload: StripeCheckoutPayload) => {
    const response = await api.post<StripeCheckoutResponse>(
      `${getURL("BILLING")}/stripe/checkout`,
      payload,
    );
    return response.data;
  };

  const mutation: UseMutationResult = mutate(
    ["usePostCreateStripeCheckout"],
    createCheckout,
    options,
  );

  return mutation;
};
