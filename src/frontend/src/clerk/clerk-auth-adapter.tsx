import { useAuth } from "@clerk/clerk-react";
import { useContext, useEffect } from "react";
import { Cookies } from "react-cookie";
import { AuthContext } from "@/contexts/authContext";
import useAuthStore from "@/stores/authStore";
import { LANGFLOW_API_TOKEN, LANGFLOW_ACCESS_TOKEN } from "@/constants/constants";
import { api } from "@/controllers/API/api";

export default function ClerkAuthAdapter() {
  const { session, getToken } = useAuth();
  const { login } = useContext(AuthContext);

  useEffect(() => {
    async function sync() {
      const token = await getToken();
      const cookies = new Cookies();

      if (token) {
        // use the same login helper used by the normal flow
        login(token, "login");
        // refreshToken not needed
        const { data } = await api.get("/api/v1/users/whoami");
        cookies.set(LANGFLOW_API_TOKEN, data.store_api_key, { path: "/" });
      } else {
        useAuthStore.getState().logout();
        cookies.remove(LANGFLOW_API_TOKEN);
        cookies.remove(LANGFLOW_ACCESS_TOKEN);
      }
    }

    sync();
  }, [session, getToken]);

  return null;
}
