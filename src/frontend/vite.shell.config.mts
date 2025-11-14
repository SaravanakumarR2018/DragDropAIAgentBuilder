import react from "@vitejs/plugin-react-swc";
import * as dotenv from "dotenv";
import path from "path";
import { defineConfig, loadEnv } from "vite";
import tsconfigPaths from "vite-tsconfig-paths";
import {
  API_ROUTES,
  BASENAME,
  PORT,
  PROXY_TARGET,
} from "./src/customization/config-constants";

const shellRoot = path.resolve(__dirname, "shell");

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");

  const envLangflowResult = dotenv.config({
    path: path.resolve(__dirname, "../../.env"),
  });

  const envLangflow = envLangflowResult.parsed || {};

  const apiRoutes = API_ROUTES || ["^/api/v1/", "^/api/v2/", "/health"];

  const target = env.VITE_PROXY_TARGET || PROXY_TARGET || "http://localhost:7860";

  const port = Number(env.VITE_PORT) || PORT || 3000;

  const proxyTargets = apiRoutes.reduce((proxyObj, route) => {
    proxyObj[route] = {
      target,
      changeOrigin: true,
      secure: false,
      ws: true,
    };
    return proxyObj;
  }, {} as Record<string, unknown>);

  const assetsDir = "shell-assets";

  return {
    root: shellRoot,
    base: BASENAME || "",
    resolve: {
      alias: {
        "@": path.resolve(__dirname, "src"),
      },
    },
    build: {
      outDir: path.resolve(__dirname, "build-shell"),
      emptyOutDir: true,
      assetsDir,
      rollupOptions: {
        output: {
          entryFileNames: `${assetsDir}/[name].[hash].js`,
          chunkFileNames: `${assetsDir}/[name].[hash].js`,
          assetFileNames: `${assetsDir}/[name].[hash].[ext]`,
        },
      },
    },
    define: {
      "process.env.BACKEND_URL": JSON.stringify(
        envLangflow.BACKEND_URL ?? "http://localhost:7860",
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
    plugins: [
      react(),
      tsconfigPaths({
        projects: [
          path.resolve(__dirname, "tsconfig.json"),
          path.resolve(shellRoot, "tsconfig.json"),
        ],
      }),
    ],
    server: {
      port,
      proxy: {
        ...proxyTargets,
      },
      fs: {
        allow: [shellRoot, path.resolve(__dirname, "src")],
      },
    },
  };
});
