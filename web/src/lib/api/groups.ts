// Typed client for the group endpoints -- see internal/handlers/group.go
// for the server side of every shape here. Every binary field crosses the
// wire as standard-padded base64, matching decodeBase64Field's own
// expectation, the same convention auth.ts's endpoints already use.

import { ApiError } from './auth.js'

export interface WireArgon2Params {
  readonly memoryKiB: number
  readonly iterations: number
  readonly parallelism: number
}

export interface WireWrappedBlob {
  readonly nonce: string
  readonly ciphertext: string
}

/**
 * The wire shape of an X25519-ECIES wrap -- distinct from WireWrappedBlob
 * (a plain Argon2id-derived AES-GCM wrap, which every auth.ts endpoint
 * uses instead): an ECIES wrap additionally carries the ephemeral public
 * key generated for it, without which it can never be unwrapped again. See
 * internal/models/models.go's WrappedKey and web/src/lib/crypto/group.ts's
 * own doc comments for the full reasoning.
 */
export interface WireWrappedKey {
  readonly ephemeralPub: string
  readonly nonce: string
  readonly ciphertext: string
}

async function putOrPostJSON<T>(method: 'POST' | 'PUT', path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  })
  return handleJSON<T>(res)
}

async function handleJSON<T>(res: Response): Promise<T> {
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
    const code =
      typeof data === 'object' && data !== null && 'code' in data && typeof data.code === 'string'
        ? data.code
        : undefined
    throw new ApiError(res.status, message, code)
  }
  return data as T
}

/**
 * The wire shape of POST /api/groups -- see internal/handlers/group.go's
 * createGroupRequest for the server side, including why groupId is
 * client-generated (idgen.ValidUUID's shape) rather than assigned by the
 * server: the signatures below must cover the real group id, which the
 * client has to know before it signs, before this request is ever sent.
 */
export interface CreateGroupRequest {
  readonly groupId: string
  readonly visibility: 'private' | 'public'
  readonly namePlaintext?: string
  readonly descriptionPlaintext?: string
  readonly nameCiphertext?: WireWrappedBlob
  readonly descriptionCiphertext?: WireWrappedBlob
  readonly revocationMode: 'rotating' | 'open'
  /** 0 means "never expire" -- only accepted when this deployment allows it (GET /api/config's allowGroupExpirationOff). */
  readonly expirationDays: number
  readonly groupKeyWrapped: WireWrappedKey
  readonly trustAnchorSignature: string
  /** The sort key rootGrantSignature is signed for -- see SignGroupCreationResult's own doc comment. */
  readonly rootGrantSortKey: string
  readonly rootGrantSignature: string
}

export interface CreateGroupResponse {
  readonly groupId: string
  readonly rootGrantSortKey: string
}

/**
 * One group in GET /api/groups's response -- see
 * internal/handlers/group.go's groupListEntry for the server side. Exactly
 * one of the two field pairs is populated, matching visibility: a public
 * group's plaintext name/description, or a private group's ciphertext plus
 * the caller's own wrappedGroupKey (needed to ever decrypt it) -- never
 * both, and a consumer should not assume the other pair is merely absent
 * rather than meaningless for that entry's visibility.
 *
 * No unread count -- see groupListEntry's own doc comment on the Go side
 * for why issue #35 ships without one despite its own one-line description
 * mentioning it.
 */
export interface GroupListEntry {
  readonly groupId: string
  readonly visibility: 'private' | 'public'
  readonly role: 'admin' | 'ambassador' | 'member'
  readonly generation: number

  readonly namePlaintext?: string
  readonly descriptionPlaintext?: string

  readonly nameCiphertext?: WireWrappedBlob
  readonly descriptionCiphertext?: WireWrappedBlob
  readonly wrappedGroupKey?: WireWrappedKey
}

export interface ListGroupsResponse {
  readonly groups: readonly GroupListEntry[]
}

/**
 * GET /api/groups -- issue #35, "the hottest read in the application"
 * (that issue's own description). Authenticated by the session cookie, like
 * every other endpoint in this file; unlike them, this is the one GET here,
 * so it doesn't fit putOrPostJSON's POST/PUT shape and calls fetch directly
 * instead, reusing the same handleJSON error handling.
 */
export async function listGroups(): Promise<ListGroupsResponse> {
  const res = await fetch('/api/groups', { credentials: 'same-origin' })
  return handleJSON<ListGroupsResponse>(res)
}

/**
 * POST /api/groups -- issue #34. Authenticated by the session cookie.
 * Throws ApiError(409, code: 'group_id_taken') on a genuine groupId
 * collision -- the server (db.isOwnGroupCreation) already ruled out "this
 * is my own earlier request being resent after a lost response" before
 * returning this, so reaching it means the id itself is unusable: the
 * caller must generate a fresh groupId and resign everything under it, not
 * retry this exact request. See runCreateGroup.ts's own handling of
 * 'group_id_taken' for why this is NOT treated the same as a plain
 * ambiguous network failure.
 */
export async function createGroup(req: CreateGroupRequest): Promise<CreateGroupResponse> {
  return putOrPostJSON<CreateGroupResponse>('POST', '/api/groups', req)
}
