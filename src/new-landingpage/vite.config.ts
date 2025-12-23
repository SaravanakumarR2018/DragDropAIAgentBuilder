import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react-swc";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "VITE_");
  const base = env.VITE_LANDING_BASE ?? "/new/landingpage/";

  return {
    plugins: [react()],
    base,
    build: {
      outDir: "dist",
      emptyOutDir: true,
    },
  };
});