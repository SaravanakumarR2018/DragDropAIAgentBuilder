import { useEffect, useMemo } from "react";
import { AxiosError } from "axios";
import * as fetchIntercept from "fetch-intercept";

import { useLogout } from "@/clerk/auth";
import { useCustomApiHeaders } from "@/customization/hooks/use-custom-api-headers";
import { customGetAccessToken } from "@/customization/utils/custom-get-access-token";
import { api } from "@/controllers/API/api";

function isExternalURL(url: string): boolean {
  const EXTERNAL_DOMAINS = [
    "https://raw.githubusercontent.com",
    "https://api.github.com",
    "https://api.segment.io",
    "https://cdn.sprig.com",
  ];

  try {
    const parsedURL = new URL(url);
    return EXTERNAL_DOMAINS.some((domain) => parsedURL.origin === domain);
  } catch (e) {
    return false;
  }
}

export function LandingApiInterceptor() {
  const customHeaders = useCustomApiHeaders();
  const serializedHeaders = useMemo(
    () => JSON.stringify(customHeaders ?? {}),
    [customHeaders],
  );
  const { mutate: triggerLogout } = useLogout();

  useEffect(() => {
    const unregister = fetchIntercept.register({
      request: function (url, config: any) {
        const accessToken = customGetAccessToken();

        config.headers = config.headers ?? {};

        if (accessToken && !config.headers["Authorization"]) {
          config.headers["Authorization"] = `Bearer ${accessToken}`;
        }

        if (!isExternalURL(url)) {
          const parsedHeaders = JSON.parse(serializedHeaders) as Record<string, string>;
          for (const [key, value] of Object.entries(parsedHeaders)) {
            config.headers[key] = value;
          }
        }

        return [url, config];
      },
    });

    const requestInterceptor = api.interceptors.request.use((config) => {
      const token = customGetAccessToken();

      config.headers = config.headers ?? {};

      if (token && !config.headers["Authorization"]) {
        config.headers["Authorization"] = `Bearer ${token}`;
      }

      if (config.url && !isExternalURL(config.url)) {
        const parsedHeaders = JSON.parse(serializedHeaders) as Record<string, string>;
        for (const [key, value] of Object.entries(parsedHeaders)) {
          config.headers[key] = value;
        }
      }

      return config;
    });

    const responseInterceptor = api.interceptors.response.use(
      (response) => response,
      async (error: AxiosError) => {
        const status = error?.response?.status;

        if (status === 401 || status === 403) {
          triggerLogout();
        }

        return Promise.reject(error);
      },
    );

    return () => {
      unregister();
      api.interceptors.request.eject(requestInterceptor);
      api.interceptors.response.eject(responseInterceptor);
    };
  }, [serializedHeaders, triggerLogout]);

  return null;
}
