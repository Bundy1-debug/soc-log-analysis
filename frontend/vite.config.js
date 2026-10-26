import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built into webapp/static/app/; Flask serves assets from /static/app/ and index.html at /.
export default defineConfig({
  plugins: [react()],
  base: "/static/app/",
  build: {
    outDir: "../webapp/static/app",
    emptyOutDir: true,
  },
  server: {
    // `npm run dev` proxies API calls to the Flask backend on :5000
    proxy: {
      "/analyze": "http://127.0.0.1:5000",
      "/analyze-sample": "http://127.0.0.1:5000",
      "/geoip": "http://127.0.0.1:5000",
    },
  },
});
