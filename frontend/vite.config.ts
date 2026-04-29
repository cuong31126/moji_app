import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from "path"
import tailwindcss from "@tailwindcss/vite"

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) {
            return;
          }

          if (
            id.includes("react") ||
            id.includes("react-dom") ||
            id.includes("react-router")
          ) {
            return "react-vendor";
          }

          if (id.includes("@radix-ui")) {
            return "radix-ui";
          }

          if (id.includes("@emoji-mart/data")) {
            return "emoji-data";
          }

          if (id.includes("@emoji-mart/react") || id.includes("emoji-mart")) {
            return "emoji-ui";
          }

          if (id.includes("lucide-react")) {
            return "icons";
          }

          if (id.includes("leaflet") || id.includes("react-leaflet")) {
            return "map-vendor";
          }

          return "vendor";
        },
      },
    },
  },
})
