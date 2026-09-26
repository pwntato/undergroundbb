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
 * POST /api/groups -- issue #34. Authenticated by the session cookie.
 * Throws ApiError(409, code: 'group_id_taken') on the astronomically rare
 * groupId collision (see db.ErrGroupIDTaken's own doc comment) -- a caller
 * hitting this must generate a fresh groupId and resign everything under
 * it, not retry this exact request, since the collision means this exact
 * id is unusable.
 */
export async function createGroup(req: CreateGroupRequest): Promise<CreateGroupResponse> {
  return putOrPostJSON<CreateGroupResponse>('POST', '/api/groups', req)
}
