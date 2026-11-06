import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The browser talks to /api; Vite forwards it to the FastAPI backend on port 8000.
const proxy = { "/api": { target: process.env.LINKGUARD_API ?? "http://127.0.0.1:8000", changeOrigin: false } };

export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy },
  preview: { port: 4173, proxy },
});
