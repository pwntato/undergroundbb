// Typed client for GET /api/users/{id} -- issue #157 -- and POST
// /api/users:batch -- issue #160; see internal/handlers/users.go. The server exposes an allowlist projection:
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
  /** A tombstoned account (#77): `username` is empty and the keys are served only so old signatures verify. */
  readonly deleted?: boolean
}

async function readJSON(res: Response): Promise<unknown> {
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
  return data
}

/** Throws ApiError(404) for an unknown user, 401 without a session. */
export async function getUser(userId: string): Promise<UserProjection> {
  const res = await fetch(`/api/users/${encodeURIComponent(userId)}`, {
    credentials: 'same-origin',
  })
  return (await readJSON(res)) as UserProjection
}

/** Ids per POST /api/users:batch; the server refuses more (db.MaxBatchUsers). */
export const USER_BATCH_SIZE = 100

async function postBatch(chunk: readonly string[]): Promise<{ users?: readonly UserProjection[] }> {
  const res = await fetch('/api/users:batch', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids: chunk }),
  })
  return (await readJSON(res)) as { users?: readonly UserProjection[] }
}

/**
 * The projections of every readable user among `ids`, keyed by id, in as few
 * requests as the cap allows (a 1,000-member roster is 10, not 1,000). Never
 * throws: an id the server does not know, and every id in a request that
 * failed (401, 503, a network error), is simply absent, so callers treat
 * "absent" as unreadable exactly as they treated a failed getUser. The server
 * answers 503 rather than "not found" for users it could not read, so a
 * throttled read is never mistaken for a missing user. A 503 means "try
 * again", so a chunk that gets one is retried once before its ids are given up
 * on. `onError` receives the reason a chunk failed outright (after that retry),
 * for callers that can tell the user why; ids absent without it were unknown.
 */
export async function getUsers(
  ids: readonly string[],
  onError?: (err: unknown) => void,
): Promise<ReadonlyMap<string, UserProjection>> {
  const distinct = [...new Set(ids)]
  const found = new Map<string, UserProjection>()
  for (let i = 0; i < distinct.length; i += USER_BATCH_SIZE) {
    const chunk = distinct.slice(i, i + USER_BATCH_SIZE)
    try {
      const data = await postBatch(chunk).catch((err: unknown) => {
        if (err instanceof ApiError && err.status === 503) return postBatch(chunk)
        throw err
      })
      const asked = new Set(chunk)
      for (const u of data.users ?? []) {
        // Only what was asked for: a server answer for another id is ignored.
        if (asked.has(u.userId)) found.set(u.userId, u)
      }
    } catch (err) {
      // This chunk's ids stay absent.
      onError?.(err)
    }
  }
  return found
}
