// Typed client for the caller's own signed fingerprint verifications -- issue
// #65; see internal/handlers/verifications.go. The server stores and serves
// them but verifies nothing on read: the client must check every signature
// (evaluateVerification).

import type { VerificationRecord } from '@/lib/crypto/verification'
import { ApiError } from './auth.js'

export interface ListVerificationsResponse {
  readonly verifications: readonly VerificationRecord[]
  readonly nextCursor?: string
}

async function fail(res: Response): Promise<never> {
  let message = res.statusText || 'request failed'
  let code: string | undefined
  try {
    const data: unknown = await res.json()
    if (typeof data === 'object' && data !== null) {
      if ('error' in data && typeof data.error === 'string') message = data.error
      if ('code' in data && typeof data.code === 'string') code = data.code
    }
  } catch {
    // Keep the status text.
  }
  throw new ApiError(res.status, message, code)
}

/** One page of the caller's verifications, in verified-uuid order. */
export async function listVerifications(cursor?: string): Promise<ListVerificationsResponse> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  const res = await fetch(`/api/verifications${query}`, { credentials: 'same-origin' })
  if (!res.ok) return fail(res)
  return (await res.json()) as ListVerificationsResponse
}

// A list this long means the server is not honoring nextCursor; stop.
const MAX_VERIFICATION_PAGES = 100

/** Every verification the caller has, following nextCursor. Throws if it cannot finish. */
export async function listAllVerifications(): Promise<VerificationRecord[]> {
  const out: VerificationRecord[] = []
  let cursor: string | undefined
  for (let page = 0; page < MAX_VERIFICATION_PAGES; page++) {
    const res = await listVerifications(cursor)
    out.push(...res.verifications)
    if (!res.nextCursor) return out
    cursor = res.nextCursor
  }
  throw new Error('verification pagination did not terminate')
}

export interface PutVerificationRequest {
  readonly fingerprint: string
  readonly verifierSigningPublicKey: string
  readonly signature: string
}

/** PUT /api/verifications/{userId}; replaces any earlier record. 204 on success. */
export async function putVerification(
  verifiedUserId: string,
  req: PutVerificationRequest,
): Promise<void> {
  const res = await fetch(`/api/verifications/${encodeURIComponent(verifiedUserId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(req),
  })
  if (!res.ok) return fail(res)
}

/** DELETE /api/verifications/{userId}: withdraws the caller's own record. 204 either way. */
export async function deleteVerification(verifiedUserId: string): Promise<void> {
  const res = await fetch(`/api/verifications/${encodeURIComponent(verifiedUserId)}`, {
    method: 'DELETE',
    credentials: 'same-origin',
  })
  if (!res.ok) return fail(res)
}
