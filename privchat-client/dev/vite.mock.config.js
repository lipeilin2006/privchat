import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@tauri-apps/api/core": resolve(__dirname, "mock/core.js"),
      "@tauri-apps/api/event": resolve(__dirname, "mock/event.js"),
    },
  },
  build: { outDir: "dist-mock" },
});
