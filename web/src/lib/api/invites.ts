// Typed client for the invite handshake endpoints -- see
// internal/handlers/invite.go for the server side of every shape here.
// Every binary field crosses the wire as standard-padded base64, matching
// groups.ts's own convention.

import { ApiError } from './auth.js'
import type { WireWrappedKey } from './groups.js'

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  })
  return handleJSON<T>(res)
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { credentials: 'same-origin' })
  return handleJSON<T>(res)
}

/** No response body expected -- revokeInvite's own 204. */
async function del(path: string): Promise<void> {
  const res = await fetch(path, { method: 'DELETE', credentials: 'same-origin' })
  if (res.ok) {
    return
  }
  // handleJSON expects a body to parse -- a DELETE error response still
  // carries the usual {error, code} JSON shape (WriteError/
  // WriteErrorWithCode), so this reuses it rather than duplicating the
  // parsing.
  await handleJSON(res)
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
 * The wire shape of POST /api/groups/{groupId}/invites -- issue #38. See
 * internal/handlers/invite.go's createInviteRequest for the server side,
 * including why inviteId is client-generated (idgen.ValidUUID's shape)
 * rather than assigned by the server: creationSignature must cover the
 * real invite id, which the client has to know before it signs, before
 * this request is ever sent.
 */
export interface CreateInviteRequest {
  readonly inviteId: string
  /** RFC 3339 (UTC). Must be between 1 hour and 30 days from now. */
  readonly expiresAt: string
  readonly creationSignature: string
}

export interface CreateInviteResponse {
  readonly inviteId: string
}

/**
 * POST /api/groups/{groupId}/invites -- issue #38. Authenticated by the
 * session cookie; the caller must hold Admin or Ambassador in groupId
 * (checked server-side; a plain Member gets a 403 before any signature is
 * even checked).
 */
export async function createInvite(
  groupId: string,
  req: CreateInviteRequest,
): Promise<CreateInviteResponse> {
  return postJSON<CreateInviteResponse>(`/api/groups/${groupId}/invites`, req)
}

/**
 * One invite's shape as GET /api/invites/{id} returns it -- issue #39. See
 * internal/handlers/invite.go's getInviteResponse for the server side.
 * Unauthenticated: an invite is a link handed to someone who may not have
 * an account yet, so this is reachable before signup.
 *
 * inviterWrappingPublicKey is read fresh from the inviter's own current
 * PROFILE, not part of the signed step-1 payload -- see the Go side's own
 * doc comment for why it exists solely to let this client recompute and
 * check the fingerprint carried in the invite link's URL fragment
 * (docs/DESIGN.md: "so the invitee's client can check it against a value
 * the server never saw").
 */
export interface GetInviteResponse {
  readonly groupId: string
  readonly inviterUserId: string
  readonly inviterSigningPublicKey: string
  readonly inviterWrappingPublicKey: string
  readonly expiresAt: string
  readonly creationSignature: string
  readonly accepted: boolean
}

/**
 * GET /api/invites/{id} -- issue #39. Throws ApiError(404) if the invite
 * does not exist (never created, or already TTL-swept after expiry), and
 * ApiError(410) if it is past its signed expiry and not yet swept (#158); an
 * invite accepted before it expired stays readable (accepted: true).
 */
export async function getInvite(inviteId: string): Promise<GetInviteResponse> {
  return getJSON<GetInviteResponse>(`/api/invites/${inviteId}`)
}

/**
 * DELETE /api/invites/{id} -- docs/DESIGN.md's revocation remedy: "before
 * acceptance that is the only remedy for a link sent to the wrong address
 * or known to have leaked." Authenticated as the invite's own inviter.
 * Throws ApiError(404) if the invite does not exist or the caller is not
 * its inviter (the same shape, deliberately -- see the Go side's own doc
 * comment), or ApiError(409, code: 'invite_already_accepted') if it has
 * already moved past step 1.
 */
export async function revokeInvite(inviteId: string): Promise<void> {
  await del(`/api/invites/${inviteId}`)
}

/**
 * The wire shape of POST /api/invites/{id}/accept -- issue #39, step 2. See
 * internal/handlers/invite.go's acceptInviteRequest for the server side.
 * Authenticated: the invitee's ed25519Pub/x25519Pub are read from their own
 * session-authenticated PROFILE server-side, not sent in this request.
 */
export interface AcceptInviteRequest {
  readonly acceptanceSignature: string
  /**
   * MAC_k(inviteAcceptancePayload(...)), k being the per-invite MAC key
   * carried in the invite link's own URL fragment -- see
   * deriveInviteMACKey's own doc comment (web/src/lib/crypto/invite.ts)
   * for what this proves that acceptanceSignature alone does not. Opaque
   * to the server: it is stored and served back at
   * GET /api/invites/pending-completions purely so the inviter's own
   * client can re-derive k and verify it there, at step 3 -- this endpoint
   * neither checks nor can check it.
   */
  readonly inviteMAC: string
}

export interface AcceptInviteResponse {
  readonly groupId: string
}

/**
 * POST /api/invites/{id}/accept -- issue #39, step 2. Throws
 * ApiError(409, code: 'invite_already_accepted') if a different holder of
 * the same link already accepted first (the single-use guarantee), or
 * ApiError(410) if the invite's signed expiry has passed, or ApiError(404)
 * if it never existed or was already TTL-swept.
 */
export async function acceptInvite(
  inviteId: string,
  req: AcceptInviteRequest,
): Promise<AcceptInviteResponse> {
  return postJSON<AcceptInviteResponse>(`/api/invites/${inviteId}/accept`, req)
}

/**
 * One invite in GET /api/invites/pending-completions's response -- issue
 * #40, step 3's discovery query. See
 * internal/handlers/invite.go's pendingInviteCompletionEntry for the
 * server side. Carries everything the inviter's own client needs to wrap
 * the group key to the invitee's signed keys and re-verify
 * acceptanceSignature itself before ever calling completeInvite.
 */
export interface PendingInviteCompletion {
  readonly inviteId: string
  readonly groupId: string
  readonly invitedUserId: string
  readonly invitedEd25519PublicKey: string
  readonly invitedX25519PublicKey: string
  readonly acceptanceSignature: string
  /** See AcceptInviteRequest.inviteMAC's own doc comment -- what completeInviteCrypto verifies before ever wrapping the group key. */
  readonly inviteMAC: string
}

export interface PendingInviteCompletionsResponse {
  readonly invites: readonly PendingInviteCompletion[]
}

/**
 * GET /api/invites/pending-completions -- issue #40, step 3's discovery
 * query. Authenticated as the inviter; returns only THIS caller's own
 * accepted-but-not-yet-completed invites.
 */
export async function pendingInviteCompletions(): Promise<PendingInviteCompletionsResponse> {
  return getJSON<PendingInviteCompletionsResponse>('/api/invites/pending-completions')
}

/**
 * The wire shape of POST /api/invites/{id}/complete -- issue #40, step 3.
 * See internal/handlers/invite.go's completeInviteRequest for the server
 * side. Deliberately has no invitedUserId field -- the server looks up
 * which invitee this invite belongs to from the caller's OWN pending
 * completions, never from a request-supplied identity.
 */
/** The inviter's signed record of an admission (#178); see admissionPayload. */
export interface WireAdmission {
  /** The inviter's own current grant address (the creator's is the root grant). */
  readonly inviterGrantRef: string
  /** UTC date, YYYY-MM-DD. */
  readonly day: string
  /** Base64 signature under SigningContext.Admission. */
  readonly signature: string
}

export interface CompleteInviteRequest {
  readonly wrappedGroupKey: WireWrappedKey
  readonly generation: number
  readonly admission: WireAdmission
}

/**
 * POST /api/invites/{id}/complete -- issue #40, step 3. Authenticated as
 * the inviter. Throws ApiError(404) if the caller has no pending
 * completion with this id (including when called by anyone other than the
 * real inviter), or ApiError(409, code: 'already_member') if the invitee
 * already holds a membership in this group some other way.
 */
export async function completeInvite(inviteId: string, req: CompleteInviteRequest): Promise<void> {
  await postJSON<{ status: string }>(`/api/invites/${inviteId}/complete`, req)
}

/**
 * One invite in GET /api/invites/sent -- issue #41. See
 * internal/handlers/invite.go's sentInviteEntry. The group is an id only (a
 * private group's name is ciphertext); resolve it from the caller's own
 * group list.
 */
export interface SentInvite {
  readonly inviteId: string
  readonly groupId: string
  /** The signed expires_at, RFC 3339. */
  readonly expiresAt: string
  /** True once an invitee accepted; the invite then awaits this inviter's step 3 and can no longer be revoked. */
  readonly accepted: boolean
  /** Present only when accepted: the date step 3 was due by. RFC 3339. */
  readonly completionDeadline?: string
  /** True when accepted and the deadline has passed with step 3 still undone (#83). */
  readonly overdue?: boolean
  /** Present only when accepted: when the server may sweep the row; until then an overdue invite stays listed. RFC 3339. */
  readonly removalDate?: string
}

export interface SentInvitesResponse {
  readonly invites: readonly SentInvite[]
}

/** GET /api/invites/sent -- issue #41. The caller's own outstanding invites. */
export async function sentInvites(): Promise<SentInvitesResponse> {
  return getJSON<SentInvitesResponse>('/api/invites/sent')
}

/**
 * One invite in GET /api/invites/received -- issue #41. Always an invite the
 * caller already accepted and that is waiting on its inviter (an invitee has
 * no record of an invite before accepting).
 */
export interface ReceivedInvite {
  readonly inviteId: string
  readonly groupId: string
  readonly inviterUserId: string
  readonly completionDeadline: string
  /** True when the deadline has passed and the inviter still has not completed (#83). */
  readonly overdue?: boolean
  /** When the server may sweep the row; after this the acceptance silently disappears. RFC 3339. */
  readonly removalDate: string
}

export interface ReceivedInvitesResponse {
  readonly invites: readonly ReceivedInvite[]
}

/** GET /api/invites/received -- issue #41. */
export async function receivedInvites(): Promise<ReceivedInvitesResponse> {
  return getJSON<ReceivedInvitesResponse>('/api/invites/received')
}
