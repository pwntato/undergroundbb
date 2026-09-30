// Typed client for the caller's own signed key pins -- issue #63; see
// internal/handlers/pins.go. The server stores and serves pins but verifies
// nothing on read: the client must check every signature (evaluatePin).

import type { PinRecord } from '@/lib/crypto/pin'
import { ApiError } from './auth.js'

export interface ListPinsResponse {
  readonly pins: readonly PinRecord[]
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

/** One page of the caller's pins, in pinned-uuid order. */
export async function listPins(cursor?: string): Promise<ListPinsResponse> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  const res = await fetch(`/api/pins${query}`, { credentials: 'same-origin' })
  if (!res.ok) return fail(res)
  return (await res.json()) as ListPinsResponse
}

// A list this long means the server is not honoring nextCursor; stop.
const MAX_PIN_PAGES = 100

/** Every pin the caller has, following nextCursor. Throws if it cannot finish. */
export async function listAllPins(): Promise<PinRecord[]> {
  const out: PinRecord[] = []
  let cursor: string | undefined
  for (let page = 0; page < MAX_PIN_PAGES; page++) {
    const res = await listPins(cursor)
    out.push(...res.pins)
    if (!res.nextCursor) return out
    cursor = res.nextCursor
  }
  throw new Error('pin pagination did not terminate')
}

export interface PutPinRequest {
  readonly signingPublicKeys: readonly string[]
  readonly wrappingPublicKey: string
  readonly pinnerSigningPublicKey: string
  readonly signature: string
}

/** PUT /api/pins/{userId}; replaces any earlier pin. 204 on success. */
export async function putPin(pinnedUserId: string, req: PutPinRequest): Promise<void> {
  const res = await fetch(`/api/pins/${encodeURIComponent(pinnedUserId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(req),
  })
  if (!res.ok) return fail(res)
}
