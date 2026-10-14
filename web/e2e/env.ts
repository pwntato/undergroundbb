// Shared by playwright.config.ts and the specs.

export const BASE_URL = process.env['E2E_BASE_URL'] ?? 'https://undergroundbb.com'

// Opts every request in as an automated test account (internal/models.TestAccountHeader).
// The server only accepts a signup carrying it with a `zz-delete-test-` username (and
// refuses that username without it), and the scheduled purge deletes those accounts.
export const TEST_ACCOUNT_HEADERS = { 'X-Test-Account': '1' }
