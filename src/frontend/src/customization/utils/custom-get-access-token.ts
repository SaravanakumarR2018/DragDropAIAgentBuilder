import { Cookies } from "react-cookie";
import { LANGFLOW_ACCESS_TOKEN } from "@/constants/constants";

export const customGetAccessToken = () => {
  return cookieManager.get(LANGFLOW_ACCESS_TOKEN);
};
