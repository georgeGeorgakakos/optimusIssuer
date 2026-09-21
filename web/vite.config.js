import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The built assets are embedded into the Go binary, so the output directory is
// the one cmd/issuerd embeds. Keep these in step.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../cmd/issuerd/webdist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": { target: "http://localhost:8090", changeOrigin: true },
    },
  },
});
