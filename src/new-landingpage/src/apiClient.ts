export const API_BASE = (import.meta.env.VITE_LANGFLOW_API_BASE ?? "/api/v1/")
  .replace(/\/?$/, "/");

export class HttpError extends Error {
  status: number;
  data: Record<string, any> | null;

  constructor(status: number, message: string, data: Record<string, any> | null) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

export function apiUrl(path: string) {
  return `${API_BASE}${path.replace(/^\/+/, "")}`;
}

export async function requestJson(
  path: string,
  {
    method = "GET",
    headers = {},
    body,
    token,
    expectJson = true,
  }: {
    method?: string;
    headers?: Record<string, string>;
    body?: BodyInit | null;
    token?: string;
    expectJson?: boolean;
  } = {},
) {
  const finalHeaders: Record<string, string> = {
    Accept: "application/json",
    ...headers,
  };

  if (body && !(body instanceof FormData) && !headers["Content-Type"]) {
    finalHeaders["Content-Type"] =
      body instanceof URLSearchParams
        ? "application/x-www-form-urlencoded"
        : "application/json";
  }

  if (token) {
    finalHeaders["Authorization"] = `Bearer ${token}`;
  }

  const response = await fetch(apiUrl(path), {
    method,
    headers: finalHeaders,
    body: body ?? undefined,
  });

  const text = expectJson ? await response.text() : null;
  let data: Record<string, any> | null = null;

  if (text) {
    try {
      data = JSON.parse(text) as Record<string, any>;
    } catch {
      data = null;
    }
  }

  if (!response.ok) {
    const detail =
      (data?.detail as string) ??
      (text ? text.slice(0, 200) : null) ??
      response.statusText;
    throw new HttpError(response.status, detail || "Request failed", data);
  }

  return data;
}
