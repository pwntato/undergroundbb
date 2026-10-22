// Typed client for key rotation (#62): POST /api/account/rotate-keys and the
// handoff rows that come before it. See internal/handlers/keyrotation.go for
// the server side and docs/DESIGN.md, "What a rotation writes".

import type { WireArgon2Params, WireWrappedBlob } from './auth.js'
import { ApiError } from './auth.js'

/**
 * A 409 that names the groups it is about (handoff_required,
 * handoff_pending, rotation_in_progress): the flow re-sends or waits on
 * exactly those.
 */
export class GroupsConflictError extends ApiError {
  readonly groups: readonly string[]
  constructor(message: string, code: string | undefined, groups: readonly string[]) {
    super(409, message, code)
    this.name = 'GroupsConflictError'
    this.groups = groups
  }
}

async function fail(res: Response): Promise<never> {
  let message = res.statusText || 'request failed'
  let code: string | undefined
  let groups: string[] | undefined
  try {
    const data: unknown = await res.json()
    if (typeof data === 'object' && data !== null) {
      if ('error' in data && typeof data.error === 'string') message = data.error
      if ('code' in data && typeof data.code === 'string') code = data.code
      if ('groups' in data && Array.isArray(data.groups)) {
        groups = data.groups.filter((g): g is string => typeof g === 'string')
      }
    }
  } catch {
    // Keep the status text.
  }
  if (res.status === 409 && groups !== undefined) {
    throw new GroupsConflictError(message, code, groups)
  }
  throw new ApiError(res.status, message, code)
}

export interface WireWrappedKey {
  readonly ephemeralPub: string
  readonly nonce: string
  readonly ciphertext: string
}

export interface HandoffEntry {
  readonly groupId: string
  readonly generation: number
  readonly newWrappingPublicKey: string
  readonly wrappedGroupKey: WireWrappedKey
}

export interface PutHandoffRequest {
  readonly generation: number
  readonly newWrappingPublicKey: string
  readonly wrappedGroupKey: WireWrappedKey
}

/**
 * PUT /api/account/rotation-handoff/{groupId}; replaces an earlier row for a
 * key that is not the account's current one. 204 on success. 409 codes:
 * `handoff_stale` (not an admin of the group at that generation, or the group's
 * key moved), `handoff_pending` (a row for the current key is waiting to be
 * used), `key_epoch_stale` (the account's keys changed). 400 for a key equal
 * to the current one.
 */
export async function putHandoff(groupId: string, req: PutHandoffRequest): Promise<void> {
  const res = await fetch(`/api/account/rotation-handoff/${encodeURIComponent(groupId)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(req),
  })
  if (!res.ok) return fail(res)
}

/** DELETE /api/account/rotation-handoff/{groupId}; deleting a row that is not there succeeds. 204. */
export async function deleteHandoff(groupId: string): Promise<void> {
  const res = await fetch(`/api/account/rotation-handoff/${encodeURIComponent(groupId)}`, {
    method: 'DELETE',
    credentials: 'same-origin',
  })
  if (!res.ok) return fail(res)
}

/** GET /api/account/rotation-handoff: the caller's own rows, ciphertext only. */
export async function listHandoffs(): Promise<readonly HandoffEntry[]> {
  const res = await fetch('/api/account/rotation-handoff', { credentials: 'same-origin' })
  if (!res.ok) return fail(res)
  const data = (await res.json()) as { handoffs: HandoffEntry[] }
  return data.handoffs
}

export interface RotateKeysRequest {
  readonly expectedKeyEpoch: number
  readonly expectedCredentialVersion: number
  readonly signedDay: string
  readonly newSigningPublicKey: string
  readonly newWrappingPublicKey: string
  readonly roster: readonly string[]
  readonly oldSignature: string
  readonly newSignature: string

  readonly salt: string
  readonly argon2Params: WireArgon2Params
  readonly wrappedPrivateKeys: WireWrappedBlob

  readonly recoverySalt: string
  readonly recoveryArgon2Params: WireArgon2Params
  readonly recoveryWrappedPrivateKeys: WireWrappedBlob

  readonly recoveryVerifierSalt: string
  readonly recoveryVerifierParams: WireArgon2Params
  readonly recoveryVerifier: string
}

export interface RotateKeysResponse {
  readonly keyEpoch: number
  readonly credentialVersion: number
}

/**
 * POST /api/account/rotate-keys. On success the server has replaced the keys
 * and every session, and answers with a fresh session cookie. Failures:
 *   - 409 `handoff_required` / `handoff_pending` / `rotation_in_progress`
 *     (GroupsConflictError, naming the groups), 409 `handoff_changed` (a
 *     handoff row moved while the request was checked; start over),
 *     409 `key_epoch_stale`, 409 with no code (the credentials changed);
 *   - 429 `rotation_cooldown`;
 *   - 400 for a request the server refuses (a signature that does not verify,
 *     a key equal to the current one, a stale day).
 */
export async function rotateKeys(req: RotateKeysRequest): Promise<RotateKeysResponse> {
  const res = await fetch('/api/account/rotate-keys', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(req),
  })
  if (!res.ok) return fail(res)
  return (await res.json()) as RotateKeysResponse
}
