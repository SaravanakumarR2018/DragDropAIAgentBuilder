import react from "@vitejs/plugin-react-swc";
import * as dotenv from "dotenv";
import path from "path";
import { defineConfig, loadEnv } from "vite";
import {
  API_ROUTES,
  BASENAME,
  PORT,
  PROXY_TARGET,
} from "../frontend/src/customization/config-constants";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  const envLangflowResult = dotenv.config({
    path: path.resolve(__dirname, "../../.env"),
  });

  const envLangflow = envLangflowResult.parsed || {};

  const apiRoutes = API_ROUTES || ["^/api/v1/", "^/api/v2/", "/health"];

  const target =
    env.VITE_PROXY_TARGET || PROXY_TARGET || envLangflow.BACKEND_URL || "http://localhost:7860";

  const port = Number(env.VITE_PORT) || PORT || 3100;

  const proxyTargets = apiRoutes.reduce((proxyObj, route) => {
    proxyObj[route] = {
      target,
      changeOrigin: true,
      secure: false,
      ws: true,
    };
    return proxyObj;
  }, {} as Record<string, unknown>);

  return {
    base: BASENAME || "/",
    build: {
      outDir: "build",
      assetsDir: "shell-assets",
      rollupOptions: {
        output: {
          entryFileNames: `shell-assets/[name].[hash].js`,
          chunkFileNames: `shell-assets/[name].[hash].js`,
          assetFileNames: `shell-assets/[name].[hash].[ext]`,
        },
      },
    },
    define: {
      "process.env.BACKEND_URL": JSON.stringify(
        env.VITE_PROXY_TARGET || envLangflow.BACKEND_URL || "http://localhost:7860",
      ),
      "process.env.ACCESS_TOKEN_EXPIRE_SECONDS": JSON.stringify(
        envLangflow.ACCESS_TOKEN_EXPIRE_SECONDS ?? 60,
      ),
      "process.env.CI": JSON.stringify(envLangflow.CI ?? false),
      "process.env.LANGFLOW_AUTO_LOGIN": JSON.stringify(
        envLangflow.LANGFLOW_AUTO_LOGIN ?? true,
      ),
      "process.env.LANGFLOW_MCP_COMPOSER_ENABLED": JSON.stringify(
        envLangflow.LANGFLOW_MCP_COMPOSER_ENABLED ?? "true",
      ),
    },
    plugins: [react()],
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "../frontend/src"),
        "@queries": path.resolve(
          __dirname,
          "../frontend/src/controllers/API/queries",
        ),
      },
    },
    server: {
      port,
      proxy: {
        ...proxyTargets,
      },
    },
  };
});
