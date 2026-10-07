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
    // Several suites do real Argon2id work (credential-material, signup,
    // recovery, change-password), about 1.5s locally; a shared CI runner has
    // taken over 5s, the default, and failed an unrelated run (#163).
    testTimeout: 30_000,
  },
})
