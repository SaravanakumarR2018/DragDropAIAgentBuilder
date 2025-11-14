import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "../frontend/src"),
      "@queries": path.resolve(__dirname, "../frontend/src/controllers/API/queries"),
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
