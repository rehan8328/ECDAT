import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, "..", "");
  const apiBaseUrl = process.env.API_BASE_URL ?? env.API_BASE_URL ?? "http://127.0.0.1:8001";
  return {
    envDir: "..",
    plugins: [react()],
    server: { host: "127.0.0.1", port: Number(process.env.FRONTEND_PORT ?? env.FRONTEND_PORT), strictPort: true },
    define: { "import.meta.env.VITE_ECDAT_API_URL": JSON.stringify(apiBaseUrl) },
  };
});
