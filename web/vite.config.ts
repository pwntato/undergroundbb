import { fileURLToPath, URL } from 'node:url'

import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    // The SPA and the API share an origin in production (one CloudFront
    // distribution, two origins), so development proxies /api to the local Go
    // server rather than introducing CORS that production does not have.
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
  build: {
    // Crypto runs in a worker; keeping the target modern avoids downlevelling
    // the WASM glue code.
    target: 'es2022',
  },
})
