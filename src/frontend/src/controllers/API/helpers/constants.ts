  import { BASE_URL_API, BASE_URL_API_V2 } from "../../../constants/constants";

export const URLs = {
  TRANSACTIONS: `monitor/transactions`,
  API_KEY: `api_key`,
  FILES: `files`,
  FILE_MANAGEMENT: `files`,
  VERSION: `version`,
  MESSAGES: `monitor/messages`,
  BUILDS: `monitor/builds`,
  STORE: `store`,
  USERS: "users",
  LOGOUT: `logout`,
  CREATE_ORGANISATION: `create_organisation`,
  LOGIN: `login`,
  AUTOLOGIN: "auto_login",
  REFRESH: "refresh",
  BUILD: `build`,
  CUSTOM_COMPONENT: `custom_component`,
  FLOWS: `flows`,
  FOLDERS: `projects`,
  PROJECTS: `projects`,
  VARIABLES: `variables`,
  VALIDATE: `validate`,
  CONFIG: `config`,
  STARTER_PROJECTS: `starter-projects`,
  SIDEBAR_CATEGORIES: `sidebar_categories`,
  ALL: `all`,
  VOICE: `voice`,
  PUBLIC_FLOW: `flows/public_flow`,
  MCP: `mcp/project`,
  MCP_SERVERS: `mcp/servers`,
  KNOWLEDGE_BASES: `knowledge_bases`,
  BILLING_ACCESS: `billing/org-access`,
  GET_PADDLE_PRICES: `billing/paddle-prices`,
  GET_PADDLE_SUBSCRIPTION: `billing/get-subscriptions`,
  CANCEL_PADDLE_SUBSCRIPTION: `billing/cancel-subscription`,
  CHANGE_SUBSCRIPTION: `billing/change-subscription`,
  PREVIEW_BILLING_CHANGE: `billing/preview-change`,
  CHANGE_PLAN: `billing/change-plan`,
  CHANGE_SEATS: `billing/change-seats`,
} as const;

// IMPORTANT: FOLDERS endpoint now points to 'projects' for backward compatibility

export function getURL(
  key: keyof typeof URLs,
  params: any = {},
  v2: boolean = false,
) {
  let url = URLs[key];
  for (const paramKey of Object.keys(params)) {
    url += `/${params[paramKey]}`;
  }
  return `${v2 ? BASE_URL_API_V2 : BASE_URL_API}${url}`;
}

export type URLsType = typeof URLs;
