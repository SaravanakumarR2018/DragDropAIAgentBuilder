import { useAuth } from "@clerk/clerk-react";
import { useCallback } from "react";
import { api } from "@/controllers/API/api";
import { getURL } from "@/controllers/API/helpers/constants";

type ChangePreviewPayload = {
  seats?: number;
  price_id?: string;
};

export function usePreviewChange() {
  const { getToken } = useAuth();

  return useCallback(
    async (payload: ChangePreviewPayload) => {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing auth token");
      }

      const response = await api.post(getURL("PREVIEW_BILLING_CHANGE"), payload, {
        headers: { Authorization: `Bearer ${token}` },
      });

      return response.data;
    },
    [getToken],
  );
}

export function useChangePlan() {
  const { getToken } = useAuth();

  return useCallback(
    async (payload: { price_id: string; seats: number }) => {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing auth token");
      }

      const response = await api.post(getURL("CHANGE_PLAN"), payload, {
        headers: { Authorization: `Bearer ${token}` },
      });

      return response.data;
    },
    [getToken],
  );
}

export function useChangeSeats() {
  const { getToken } = useAuth();

  return useCallback(
    async (payload: { seats: number }) => {
      const token = await getToken();
      if (!token) {
        throw new Error("Missing auth token");
      }

      const response = await api.post(getURL("CHANGE_SEATS"), payload, {
        headers: { Authorization: `Bearer ${token}` },
      });

      return response.data;
    },
    [getToken],
  );
}