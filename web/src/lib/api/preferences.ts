// Typed client for GET and PUT /api/account/preferences (#366); see internal/handlers/preferences.go.
// The blob is opaque ciphertext the server never opens, sealed in the crypto worker under a key
// derived from the X25519 private key (lib/crypto/preferences.ts).

import type { WireWrappedBlob } from './auth.js'
import { ApiError } from './auth.js'

export interface PreferencesRead {
  /** The account's KeyEpoch: a write must name it, so one sealed before a rotation is refused. */
  readonly keyEpoch: number
  /** Absent until a blob has been written. */
  readonly preferencesBlob?: WireWrappedBlob
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

/** 401 without a session. */
export async function getPreferences(): Promise<PreferencesRead> {
  const res = await fetch('/api/account/preferences', { credentials: 'same-origin' })
  if (!res.ok) return fail(res)
  return (await res.json()) as PreferencesRead
}

/** 204 on success; 409 `key_epoch_stale` if the keys were rotated since the epoch named. */
export async function putPreferences(
  expectedKeyEpoch: number,
  preferencesBlob: WireWrappedBlob,
): Promise<void> {
  const res = await fetch('/api/account/preferences', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify({ expectedKeyEpoch, preferencesBlob }),
  })
  if (!res.ok) return fail(res)
}
