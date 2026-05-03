// import { defineConfig } from 'vite'
// import react from '@vitejs/plugin-react'
// import path from "path"
// import tailwindcss from "@tailwindcss/vite"

// // https://vite.dev/config/
// export default defineConfig({
//   plugins: [react(), tailwindcss()],
//   resolve: {
//     alias: {
//       "@": path.resolve(__dirname, "./src"),
//     },
//   },
//   build: {
//     rollupOptions: {
//       output: {
//         manualChunks(id) {
//           if (!id.includes("node_modules")) {
//             return;
//           }

//           if (id.includes("leaflet") && !id.includes("react-leaflet")) {
//             return "map-vendor";
//           }

//           return "vendor";
//         },
//       },
//     },
//   },
// })

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

          // GOM TẤT CẢ React, Leaflet và React-Leaflet vào cùng một cục
          // Điều này đảm bảo chúng luôn nhìn thấy nhau và không bị lỗi createContext
          if (
            id.includes("react") || 
            id.includes("leaflet") || 
            id.includes("scheduler") || 
            id.includes("prop-types")
          ) {
            return "vendor-core"; 
          }

          // Các thư viện còn lại (như tailwind, v.v.) sẽ nằm ở đây
          return "vendor";
        },
      },
    },
  },
})
