// Typed client for GET /api/users/{id} -- issue #157; see
// internal/handlers/users.go. The server exposes an allowlist projection:
// the username and public keys, nothing that could be used to attack a
// password offline. Keys cross the wire as standard-padded base64.

import { ApiError } from './auth.js'

export interface WireSupersededKey {
  readonly publicKey: string
  readonly from: string
  readonly until?: string
}

export interface UserProjection {
  readonly userId: string
  readonly username: string
  readonly signingPublicKey: string
  readonly wrappingPublicKey: string
  readonly supersededSigningKeys: readonly WireSupersededKey[]
}

/** Throws ApiError(404) for an unknown user, 401 without a session. */
export async function getUser(userId: string): Promise<UserProjection> {
  const res = await fetch(`/api/users/${encodeURIComponent(userId)}`, {
    credentials: 'same-origin',
  })
  let data: unknown
  try {
    data = await res.json()
  } catch {
    throw new ApiError(res.status, res.statusText || 'malformed response')
  }
  if (!res.ok) {
    const message =
      typeof data === 'object' && data !== null && 'error' in data && typeof data.error === 'string'
        ? data.error
        : res.statusText || 'request failed'
    throw new ApiError(res.status, message)
  }
  return data as UserProjection
}
