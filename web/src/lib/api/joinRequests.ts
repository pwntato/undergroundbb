// Typed client for the join-request endpoints (#72) -- see internal/handlers/join_request.go for the
// server side of every shape here. Binary fields cross the wire as standard-padded base64.

import { ApiError } from './auth.js'
import { noteServerDate } from './serverClock.js'
import type { WireAdmission } from './invites.js'
import type { WireWrappedKey } from './groups.js'

async function handleJSON<T>(res: Response): Promise<T> {
  noteServerDate(res)
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
  return handleJSON<T>(await fetch(path, { credentials: 'same-origin' }))
}

/** A response with no body (204): an error still carries the usual {error, code} JSON. */
async function noContent(path: string, method: 'DELETE' | 'POST'): Promise<void> {
  const res = await fetch(path, { method, credentials: 'same-origin' })
  if (res.ok) {
    noteServerDate(res)
    return
  }
  await handleJSON(res)
}

const base = (groupId: string): string => `/api/groups/${encodeURIComponent(groupId)}/join-requests`

function pageQuery(limit?: number, cursor?: string): string {
  const q = new URLSearchParams()
  if (limit !== undefined) q.set('limit', String(limit))
  if (cursor !== undefined && cursor !== '') q.set('cursor', cursor)
  const s = q.toString()
  return s === '' ? '' : `?${s}`
}

export interface CreateJoinRequestBody {
  /** A fresh UUID, signed into the request. */
  readonly requestId: string
  /** Base64 signature under SigningContext.JoinRequest. */
  readonly signature: string
}

/**
 * POST /api/groups/{id}/join-requests. 404 for a private or missing group; 409 with code
 * already_member, request_pending, request_cooling_off or keys_changed; 400 bad_signature.
 */
export async function createJoinRequest(
  groupId: string,
  body: CreateJoinRequestBody,
): Promise<{ requestId: string }> {
  return postJSON<{ requestId: string }>(base(groupId), body)
}

/** One pending request as an approver sees it. The approver's client verifies `signature` itself. */
export interface JoinRequestEntry {
  readonly userId: string
  readonly requestId: string
  readonly ed25519PublicKey: string
  readonly x25519PublicKey: string
  readonly signature: string
  /** UTC day the request was made, YYYY-MM-DD. */
  readonly day: string
}

export interface ListJoinRequestsResponse {
  readonly requests: readonly JoinRequestEntry[]
  readonly nextCursor?: string
}

/** GET /api/groups/{id}/join-requests -- admin or ambassador only (403 otherwise). */
export async function listJoinRequests(
  groupId: string,
  opts: { readonly limit?: number; readonly cursor?: string } = {},
): Promise<ListJoinRequestsResponse> {
  return getJSON<ListJoinRequestsResponse>(`${base(groupId)}${pageQuery(opts.limit, opts.cursor)}`)
}

/** DELETE /api/groups/{id}/join-requests/mine. 409 request_denied: a declined request cannot be withdrawn. */
export async function withdrawJoinRequest(groupId: string): Promise<void> {
  await noContent(`${base(groupId)}/mine`, 'DELETE')
}

/** POST /api/groups/{id}/join-requests/{userId}/deny. */
export async function denyJoinRequest(groupId: string, requesterUserId: string): Promise<void> {
  await noContent(`${base(groupId)}/${encodeURIComponent(requesterUserId)}/deny`, 'POST')
}

export interface ApproveJoinRequestBody {
  /** The id on the request the approver's client verified. */
  readonly requestId: string
  readonly wrappedGroupKey: WireWrappedKey
  readonly generation: number
  /** AdmissionPayload with the REQUEST id in the invite-id slot. */
  readonly admission: WireAdmission
}

/**
 * POST /api/groups/{id}/join-requests/{userId}/approve. 409 codes: group_full (the request stays
 * pending), requester_keys_changed, already_member, request_changed, grantor_ref_stale,
 * grantor_changed; 410 requester_deleted / group_gone; 400 clock_skew / bad_signature.
 */
export async function approveJoinRequest(
  groupId: string,
  requesterUserId: string,
  body: ApproveJoinRequestBody,
): Promise<void> {
  await postJSON<{ status: string }>(
    `${base(groupId)}/${encodeURIComponent(requesterUserId)}/approve`,
    body,
  )
}

/** One of the caller's own live requests. */
export interface MyJoinRequest {
  readonly groupId: string
  readonly groupName?: string
  readonly requestId: string
  readonly status: 'pending' | 'denied'
  readonly day: string
  /** UTC day a denied request's cool-off ends. */
  readonly retryAfter?: string
}

export interface MyJoinRequestsResponse {
  readonly requests: readonly MyJoinRequest[]
  readonly nextCursor?: string
}

/** GET /api/join-requests -- the caller's own live requests, oldest first, paged. */
export async function myJoinRequests(
  opts: { readonly limit?: number; readonly cursor?: string } = {},
): Promise<MyJoinRequestsResponse> {
  return getJSON<MyJoinRequestsResponse>(`/api/join-requests${pageQuery(opts.limit, opts.cursor)}`)
}
