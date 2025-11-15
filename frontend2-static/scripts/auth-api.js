const API_BASE = "/api/v1/";

async function handleResponse(response) {
  if (response.ok) {
    if (response.status === 204) return null;
    const contentType = response.headers.get("content-type") || "";
    if (contentType.includes("application/json")) {
      return response.json();
    }
    return response.text();
  }

  let detail = `Request failed with status ${response.status}`;
  try {
    const data = await response.json();
    if (typeof data?.detail === "string") {
      detail = data.detail;
    } else if (data?.detail?.message) {
      detail = data.detail.message;
    }
  } catch (_) {
    // ignore json parsing failures
  }
  const error = new Error(detail);
  error.status = response.status;
  throw error;
}

export async function createOrganisation(clerkToken) {
  const response = await fetch(`${API_BASE}create_organisation`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${clerkToken}`,
    },
    credentials: "include",
  });
  return handleResponse(response);
}

export async function ensureLangflowUser(clerkToken, username, { maxRetries = 2 } = {}) {
  let attempt = 0;
  while (attempt <= maxRetries) {
    try {
      const response = await fetch(`${API_BASE}users/whoami`, {
        headers: { Authorization: `Bearer ${clerkToken}` },
        credentials: "include",
      });
      return { justCreated: false, user: await handleResponse(response) };
    } catch (error) {
      if (error.status === 401) {
        try {
          const createResponse = await fetch(`${API_BASE}users/`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${clerkToken}`,
            },
            body: JSON.stringify({ username, password: "clerk_dummy_password" }),
            credentials: "include",
          });
          await handleResponse(createResponse);
          return { justCreated: true, user: null };
        } catch (createError) {
          if (
            createError.status === 400 &&
            typeof createError.message === "string" &&
            createError.message.includes("username is unavailable")
          ) {
            attempt += 1;
            await new Promise((resolve) => setTimeout(resolve, 150));
            continue;
          }
          throw createError;
        }
      }
      throw error;
    }
  }
  throw new Error("Unable to ensure Langflow user");
}

export async function backendLogin(username, clerkToken) {
  const body = new URLSearchParams({ username, password: "clerk_dummy_password" });
  const response = await fetch(`${API_BASE}login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Bearer ${clerkToken}`,
    },
    credentials: "include",
    body: body.toString(),
  });
  return handleResponse(response);
}
