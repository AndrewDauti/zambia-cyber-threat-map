import { defineConfig } from "vite";

// Project site: https://andrewdauti.github.io/zambia-cyber-threat-map/
export default defineConfig({
  base: "/zambia-cyber-threat-map/",
  server: {
    host: "0.0.0.0",
    port: 5173,
  },
  preview: {
    host: "0.0.0.0",
    port: 4173,
  },
});
