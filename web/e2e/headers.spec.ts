import { createHash } from 'node:crypto'

import { expect, test } from '@playwright/test'

import { BASE_URL } from './env.ts'

// The security headers come from CloudFront's response headers policy
// (terraform/cloudfront.tf), so they exist only on a deployment behind it. A local stack
// (go run ./cmd/local, vite preview) does not send them.
test.skip(
  !BASE_URL.startsWith('https://'),
  'response headers are added by CloudFront; run against a deployment',
)

// One path per CloudFront behavior that has its own response_headers_policy_id line (the
// default behavior, /assets/*, /api and /api/*), plus a client-side route, which goes through
// the SPA rewrite. The status is asserted too, so a path that stops being served cannot pass
// on an error page that happens to carry the headers. Bare /api has no route: Lambda's 404.
const PATHS: readonly { path: string; status: number }[] = [
  { path: '/', status: 200 },
  { path: '/assets/*', status: 200 },
  { path: '/groups/abc', status: 200 },
  { path: '/api/health', status: 200 },
  { path: '/api', status: 404 },
]

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

for (const { path, status } of PATHS) {
  test(`security headers on ${path}`, async ({ request }) => {
    // '/assets/*' stands for the current bundle, whose hashed name is read from the page.
    const res = await request.get(path === '/assets/*' ? await firstAssetPath(request) : path)
    expect(res.status(), 'status').toBe(status)
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
  const res = await request.get(new URL('api/health', url).href)
  expect(res.status()).toBe(403)
})

async function firstAssetPath(request: import('@playwright/test').APIRequestContext) {
  const html = await (await request.get('/')).text()
  const match = /\/assets\/[^"']+\.js/.exec(html)
  expect(match, 'a script under /assets/ in the page').not.toBeNull()
  return match![0]
}

test('every script and stylesheet in the page carries a matching integrity hash', async ({
  request,
}) => {
  // Subresource integrity (#67, web/plugins/sri.ts). Recompute each hash from the bytes the
  // site actually serves, so a build that stopped adding them, or hashed something other than
  // what was uploaded (the browser would then block the app), fails here.
  const html = await (await request.get('/')).text()
  const tags = [...html.matchAll(/<(?:script|link)\b[^>]*(?:src|href)="(\/assets\/[^"]+)"[^>]*>/g)]
  expect(tags.length, 'asset tags in the page').toBeGreaterThan(0)
  for (const [tag, path] of tags) {
    const claimed = /\sintegrity="(sha384-[^"]+)"/.exec(tag ?? '')?.[1]
    expect(claimed, `integrity on ${path}`).toBeDefined()
    const body = await (await request.get(path!)).body()
    const actual = `sha384-${createHash('sha384').update(body).digest('base64')}`
    expect(actual, `hash of ${path}`).toBe(claimed)
  }
})
