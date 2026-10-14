import { defineConfig, devices } from '@playwright/test'

import { BASE_URL, TEST_ACCOUNT_HEADERS } from './e2e/env.ts'

// Smoke tests against a live deployment (prod by default): `npm run e2e`, or
// E2E_BASE_URL=https://... npm run e2e. CI runs them after each deploy
// (.github/workflows/smoke.yml). One worker and no retries: a retry would hide a
// flaky release, and the specs share one account.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  // Signup runs Argon2id in a worker, which is slow on a shared runner.
  timeout: 120_000,
  expect: { timeout: 60_000 },
  reporter: process.env['CI'] ? [['github'], ['list']] : 'list',
  use: {
    baseURL: BASE_URL,
    extraHTTPHeaders: TEST_ACCOUNT_HEADERS,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
