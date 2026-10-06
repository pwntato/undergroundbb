// Typed client for the group endpoints -- see internal/handlers/group.go
// for the server side of every shape here. Every binary field crosses the
// wire as standard-padded base64, matching decodeBase64Field's own
// expectation, the same convention auth.ts's endpoints already use.

import type { DesignationRecord, GrantAnchor, GrantRecord } from '@/lib/crypto/grant-chain'
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
  /**
   * The key generation the private name/description ciphertext is encrypted
   * under -- what its AAD binds. Not the member's own `generation` once
   * rotation exists (rotation does not re-encrypt the name).
   */
  readonly nameGeneration: number

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

/**
 * GET /api/groups/{id}'s response -- internal/handlers/group.go's
 * groupDetailResponse: a GroupListEntry plus the settings a detail screen
 * shows. `role` is '' (absent from any real role) for a non-member viewing a
 * public group, who also gets no wrappedGroupKey. `version` is what a
 * subsequent PUT must echo back.
 */
export interface GroupDetail extends Omit<GroupListEntry, 'role'> {
  readonly role: GroupListEntry['role'] | ''
  readonly revocationMode: 'rotating' | 'open'
  /** 0 means "never expire". */
  readonly expirationDays: number
  readonly version: number
  /**
   * The caller's OWN current grant address -- what a role change must sign as
   * grantorGrantRef. Present for members only.
   */
  readonly myGrantSortKey?: string
  /**
   * The group's in-progress key rotation, members only; absent when none is
   * running. While present, new posts still use generation `generation - 1`.
   */
  readonly rotation?: {
    readonly generation: number
    readonly startedAt: string
    readonly startedBy: string
  }
}

/**
 * PUT /api/groups/{id}'s body -- a full replacement of name, description and
 * expiration policy; revocation mode and visibility are not editable. Exactly
 * one pair per visibility, like CreateGroupRequest. For a private group,
 * nameGeneration must be the caller's own current generation.
 */
export interface UpdateGroupRequest {
  readonly version: number
  readonly namePlaintext?: string
  readonly descriptionPlaintext?: string
  readonly nameCiphertext?: WireWrappedBlob
  readonly descriptionCiphertext?: WireWrappedBlob
  readonly nameGeneration?: number
  readonly expirationDays: number
}

/** GET /api/groups/{id} -- issue #36. A 404 covers "no such group" and "private and you are not in it" alike. */
export async function getGroup(groupId: string): Promise<GroupDetail> {
  const res = await fetch(`/api/groups/${encodeURIComponent(groupId)}`, {
    credentials: 'same-origin',
  })
  return handleJSON<GroupDetail>(res)
}

/**
 * PUT /api/groups/{id} -- issue #36. Admin only. Throws ApiError(409, code:
 * 'version_conflict') when another admin saved first: reload and reapply,
 * do not resend unchanged.
 */
export async function updateGroup(
  groupId: string,
  req: UpdateGroupRequest,
): Promise<{ version: number }> {
  return putOrPostJSON<{ version: number }>(
    'PUT',
    `/api/groups/${encodeURIComponent(groupId)}`,
    req,
  )
}

export type MemberRole = 'admin' | 'ambassador' | 'member'

/**
 * One row of GET /api/groups/{id}/members -- ids and roles only. A member's
 * username and keys belong to the users projection (GET /api/users/:id),
 * which does not exist yet, so the roster shows ids until it does.
 */
export interface MemberEntry {
  readonly userId: string
  readonly role: MemberRole
  readonly generation: number
}

export interface ListMembersResponse {
  readonly members: readonly MemberEntry[]
  /** Empty on the last page; pass it back as `cursor`. */
  readonly nextCursor?: string
}

/** GET /api/groups/{id}/members -- issue #37. Members only; a non-member gets the same 404 as a missing group. */
export async function listMembers(groupId: string, cursor?: string): Promise<ListMembersResponse> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  const res = await fetch(`/api/groups/${encodeURIComponent(groupId)}/members${query}`, {
    credentials: 'same-origin',
  })
  return handleJSON<ListMembersResponse>(res)
}

/**
 * GET /api/groups/{id}/grants -- issue #55. The signed role-grant history and
 * the stored chain anchor (on every page). Members only, same 404 as the
 * roster. Nothing here is verified by the server; see lib/crypto/grant-chain.
 */
export interface ListGrantsResponse {
  readonly anchor: GrantAnchor
  readonly grants: readonly GrantRecord[]
  /** Empty on the last page; pass it back as `cursor`. */
  readonly nextCursor?: string
}

export async function listGrants(groupId: string, cursor?: string): Promise<ListGrantsResponse> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  const res = await fetch(`/api/groups/${encodeURIComponent(groupId)}/grants${query}`, {
    credentials: 'same-origin',
  })
  return handleJSON<ListGrantsResponse>(res)
}

/**
 * GET /api/groups/{id}/designations: the signed successor designations (#161),
 * served the way grants are and verified by nothing server-side. Pass them to
 * lib/crypto/grant-chain so a successor's claim row can be checked.
 */
export interface ListDesignationsResponse {
  readonly designations: readonly DesignationRecord[]
  /** Empty on the last page; pass it back as `cursor`. */
  readonly nextCursor?: string
}

export async function listDesignations(
  groupId: string,
  cursor?: string,
): Promise<ListDesignationsResponse> {
  const query = cursor ? `?cursor=${encodeURIComponent(cursor)}` : ''
  const res = await fetch(`/api/groups/${encodeURIComponent(groupId)}/designations${query}`, {
    credentials: 'same-origin',
  })
  return handleJSON<ListDesignationsResponse>(res)
}

export interface PutDesignationRequest {
  /** The row's own address, signed as part of the payload. */
  readonly designationSortKey: string
  /** Empty revokes the standing designation. */
  readonly successorUserId: string
  /** 30 to 365; signed, and stored but ignored on a revocation. */
  readonly periodDays: number
  /** The caller's own current grant (GroupDetail.myGrantSortKey). */
  readonly adminGrantRef: string
  readonly signature: string
}

/**
 * PUT /api/groups/{id}/designation -- #161. Admin only: appends a signed
 * successor designation, or a revocation when successorUserId is empty.
 * 409 codes: grantor_ref_stale / grantor_changed / conflict_retry mean
 * "reload and decide again"; designation_key_taken means "sign again with a
 * fresh sort key"; grantor_granted_today (the admin's own grant is dated today)
 * and designation_today (already designated today) mean "try tomorrow": show
 * the server's message, reloading does not help. 410 subject_deleted: that
 * account was deleted.
 */
export async function putDesignation(
  groupId: string,
  req: PutDesignationRequest,
): Promise<{ sortKey: string }> {
  return putOrPostJSON('PUT', `/api/groups/${encodeURIComponent(groupId)}/designation`, req)
}

export interface ClaimDesignationRequest {
  /** The DESIGNATION# row being claimed. */
  readonly designationSortKey: string
  /** The claim row's own address (a GRANT# key for the caller), whose day is the claim day. */
  readonly claimSortKey: string
  readonly signature: string
}

/**
 * POST /api/groups/{id}/designation/claim -- #161. The designated successor
 * claims the admin role. 409 codes: not_inactive (the admin or another admin
 * was active within the period; the server's message says when to try again),
 * designation_superseded / designation_lapsed / admin_changed / already_claimed
 * / designation_not_yours / already_admin / subject_role_changed /
 * conflict_retry mean the situation changed (reload); designation_before_join
 * (you joined after it was signed) is like not_inactive: reloading cannot
 * help, show the server's message;
 * grant_key_taken means "sign again with a fresh claim sort key".
 */
export async function claimDesignation(
  groupId: string,
  req: ClaimDesignationRequest,
): Promise<{ role: MemberRole; grantSortKey: string }> {
  return putOrPostJSON('POST', `/api/groups/${encodeURIComponent(groupId)}/designation/claim`, req)
}

/** One GENKEY# chain link: generation `generation`'s key, sealed under generation+1's. */
export interface KeychainLink {
  readonly generation: number
  readonly wrapped: { readonly nonce: string; readonly ciphertext: string }
}

export interface KeychainResponse {
  readonly links: readonly KeychainLink[]
  /** The generation to pass as `from` for the next page; absent when exhausted. */
  readonly nextFrom?: number
}

/**
 * GET /api/groups/{id}/keychain?from=A&to=B -- the chain links for generations
 * A..B inclusive, ascending, members only. A generation with no link is simply
 * absent: the caller decides whether that is a gap.
 */
export async function getKeychain(
  groupId: string,
  from: number,
  to: number,
): Promise<KeychainResponse> {
  const res = await fetch(
    `/api/groups/${encodeURIComponent(groupId)}/keychain?from=${String(from)}&to=${String(to)}`,
    { credentials: 'same-origin' },
  )
  return handleJSON<KeychainResponse>(res)
}

export interface ChangeMemberRoleRequest {
  readonly role: MemberRole
  /** The new grant's own address, signed as part of the payload. */
  readonly grantSortKey: string
  /** The caller's own current grant (GroupDetail.myGrantSortKey). */
  readonly grantorGrantRef: string
  readonly signature: string
}

/**
 * PUT /api/groups/{id}/members/{uid}/role -- issue #37. Admin only, never
 * for oneself. 409 codes: grantor_ref_stale / grantor_changed /
 * subject_role_changed / conflict_retry mean "reload and decide again";
 * grant_key_taken means "sign again with a fresh grantSortKey";
 * grantor_granted_today means the caller's own grant is dated the same UTC
 * day as (or after) this one, so it could never verify: show the server's
 * message, since reloading does not help (#167).
 */
export async function changeMemberRole(
  groupId: string,
  userId: string,
  req: ChangeMemberRoleRequest,
): Promise<{ role: MemberRole; grantSortKey: string }> {
  return putOrPostJSON(
    'PUT',
    `/api/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}/role`,
    req,
  )
}

/**
 * The signed self-demotion an admin or ambassador attaches to leaving
 * (issue #55): a role grant to "member" with the caller as grantor and
 * subject. A plain member sends none.
 */
export interface LeaveGroupRequest {
  readonly grantSortKey: string
  readonly grantorGrantRef: string
  readonly signature: string
}

/**
 * POST /api/groups/{id}/leave -- issues #66, #55. 409 `last_admin` means the
 * caller is the only Admin of a group that still has other members and must
 * promote a successor first; 409 `conflict_retry` / `grantor_ref_stale` mean
 * the roster or the caller's own grant moved, reload and try again; 409
 * `grant_key_taken` means sign again with a fresh grantSortKey; 400
 * `demotion_required` means an admin or ambassador sent no demotion (their
 * role changed since the roster loaded). `groupDeleted` is true when the
 * caller was the only member, so leaving deleted the group.
 */
export async function leaveGroup(
  groupId: string,
  demotion?: LeaveGroupRequest,
): Promise<{ groupDeleted: boolean }> {
  return putOrPostJSON('POST', `/api/groups/${encodeURIComponent(groupId)}/leave`, demotion ?? {})
}

/** Like putOrPostJSON for endpoints that answer 204; throws ApiError (with the server's `code`) otherwise. */
async function sendNoContent(
  method: 'POST' | 'PUT' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<void> {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  })
  if (res.ok) {
    return
  }
  await handleJSON<never>(res)
}

/**
 * The rotation half of a Rotating-group removal (issue #58): the new
 * generation (exactly one past the remover's own), the chain link (old key
 * under the new one) and the new key wrapped for the remover. The server
 * never sees the new key unwrapped.
 */
export interface RemoveRotationRequest {
  readonly generation: number
  readonly link: WireWrappedBlob
  readonly removerWrappedKey: WireWrappedKey
}

/**
 * The body of DELETE /api/groups/{id}/members/{uid}: the remover's signed
 * demotion of an admin or ambassador subject (all three fields or none), and
 * the rotation for a Rotating group (absent for an Open one).
 */
export interface RemoveMemberRequest {
  readonly grantSortKey?: string
  readonly grantorGrantRef?: string
  readonly signature?: string
  readonly rotation?: RemoveRotationRequest
}

/**
 * DELETE /api/groups/{id}/members/{uid} -- issue #58. Admin only, never
 * oneself. 409 codes: rotation_in_progress (finish the running rotation
 * first), rotation_stale_generation / grantor_ref_stale / grantor_changed /
 * subject_role_changed / conflict_retry (reload and decide again),
 * grant_key_taken (sign again with a fresh grantSortKey), grantor_grant_missing.
 * 400 `demotion_required` / `rotation_required` / `rotation_not_applicable`
 * mean the request did not match the subject's role or the group's mode.
 */
export function removeMember(
  groupId: string,
  userId: string,
  req?: RemoveMemberRequest,
): Promise<void> {
  return sendNoContent(
    'DELETE',
    `/api/groups/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`,
    req,
  )
}

/** One member's entry point wrapped for the rotation's generation. */
export interface RewrapEntry {
  readonly userId: string
  readonly wrappedKey: WireWrappedKey
}

/** The most members PUT /rotation/members takes at once (db.MaxRewrapBatch). */
export const MAX_REWRAP_BATCH = 25

/**
 * PUT /api/groups/{id}/rotation/members -- issue #58. Moves up to
 * MAX_REWRAP_BATCH members' entry points to `generation` in one all-or-nothing
 * transaction. Admin only, and the caller's own entry point must already be at
 * `generation`. 409 codes: `rotation_not_active` (the rotation finished or was
 * superseded; re-read the group), `rotation_caller_behind` (your own key is not
 * at that generation), `member_changed` (a member left or is not behind; re-list
 * and resend), `conflict_retry`.
 */
export function rewrapMembers(
  groupId: string,
  req: { readonly generation: number; readonly wraps: readonly RewrapEntry[] },
): Promise<void> {
  return sendNoContent('PUT', `/api/groups/${encodeURIComponent(groupId)}/rotation/members`, req)
}

/**
 * POST /api/groups/{id}/rotation/complete -- issue #58. Clears the marker once
 * every member is at `generation`. 409 `members_behind` means re-list and
 * re-wrap; 409 `rotation_not_active` means someone already finished it (treat
 * as done).
 */
export function completeRotation(groupId: string, generation: number): Promise<void> {
  return sendNoContent('POST', `/api/groups/${encodeURIComponent(groupId)}/rotation/complete`, {
    generation,
  })
}
