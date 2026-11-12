import { defineConfig, devices } from '@playwright/test'

// Documentation screenshots, taken from a local app (never prod). See docs/images/README.md.
export default defineConfig({
  testDir: './e2e-docs',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 240_000,
  expect: { timeout: 60_000 },
  reporter: 'list',
  use: {
    baseURL: process.env['DOCS_BASE_URL'] ?? 'http://localhost:5173',
    viewport: { width: 1100, height: 760 },
    colorScheme: 'dark',
    actionTimeout: 15_000,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1100, height: 760 } },
    },
  ],
})
