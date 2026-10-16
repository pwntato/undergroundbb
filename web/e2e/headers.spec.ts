import { expect, test } from '@playwright/test'

import { BASE_URL } from './env.ts'

// The security headers come from CloudFront's response headers policy
// (terraform/cloudfront.tf), so they exist only on a deployment behind it. A local stack
// (go run ./cmd/local, vite preview) does not send them.
test.skip(
  !BASE_URL.startsWith('https://'),
  'response headers are added by CloudFront; run against a deployment',
)

// Both origins: the SPA (S3) and the API (Lambda), plus an asset and a client-side route,
// which take different CloudFront behaviors.
const PATHS = ['/', '/assets/*', '/groups/abc', '/api/health']

const EXPECTED: Record<string, string> = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
}

const CSP_DIRECTIVES = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'none'",
  "frame-ancestors 'none'",
]

for (const path of PATHS) {
  test(`security headers on ${path}`, async ({ request }) => {
    // '/assets/*' stands for the current bundle, whose hashed name is read from the page.
    const res = await request.get(path === '/assets/*' ? await firstAssetPath(request) : path)
    const headers = res.headers()
    for (const [name, want] of Object.entries(EXPECTED)) {
      expect(headers[name], name).toBe(want)
    }
    const csp = (headers['content-security-policy'] ?? '').split('; ')
    expect(csp, 'content-security-policy').toEqual(CSP_DIRECTIVES)
  })
}

test('the Lambda Function URL refuses calls that skip CloudFront', async ({ request }) => {
  // Without the secret CloudFront adds, a direct call must not reach a handler (#103). The
  // URL is not public knowledge, so it is optional: set E2E_FUNCTION_URL to check it.
  const url = process.env['E2E_FUNCTION_URL']
  test.skip(!url, 'E2E_FUNCTION_URL not set')
  const res = await request.get(`${url}api/health`)
  expect(res.status()).toBe(403)
})

async function firstAssetPath(request: import('@playwright/test').APIRequestContext) {
  const html = await (await request.get('/')).text()
  const match = /\/assets\/[^"']+\.js/.exec(html)
  expect(match, 'a script under /assets/ in the page').not.toBeNull()
  return match![0]
}
