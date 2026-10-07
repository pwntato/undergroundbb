import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vitest/config'

export default defineConfig({
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  test: {
    environment: 'node',
    // credential-material.test.ts does real Argon2id work (up to ~2s locally);
    // a shared CI runner has taken over 5s, the default (#163). This is the one
    // place the timeout is set for the whole suite.
    testTimeout: 30_000,
  },
})
