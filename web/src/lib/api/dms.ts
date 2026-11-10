// Typed client for the direct-message endpoints (#73) -- see internal/handlers/dm.go for the
// server side of every shape here. A DM is created through POST /api/groups with a `dm` object
// (one code path with every other group); what is specific to it lives below.

import { ApiError } from './auth.js'
import { noteServerDate } from './serverClock.js'
import type { CreateGroupRequest, CreateGroupResponse, WireWrappedKey } from './groups.js'

/** 409 dm_exists: the pair already has a conversation, and this is its id. */
export class DMExistsError extends ApiError {
  readonly groupId: string
  constructor(message: string, groupId: string) {
    super(409, message, 'dm_exists')
    this.groupId = groupId
  }
}

/** The `dm` object of POST /api/groups. */
export interface CreateDMBody {
  readonly recipientUserId: string
  /** A fresh UUID, signed into the admission (the invite-id slot). */
  readonly requestId: string
  /** The Generation 0 group key wrapped to the recipient's X25519 key. */
  readonly wrappedGroupKey: WireWrappedKey
  /** Over the recipient's keys as the server serves them; the root grant is its grant ref. */
  readonly admission: { readonly day: string; readonly signature: string }
}

async function handleJSON<T>(res: Response): Promise<T> {
  noteServerDate(res)
  let data: unknown
  try {
    data = await res.json()
  } catch {
    throw new ApiError(res.status, res.statusText || 'malformed response')
  }
  if (!res.ok) {
    const field = (name: string): string | undefined =>
      typeof data === 'object' &&
      data !== null &&
      name in data &&
      typeof (data as Record<string, unknown>)[name] === 'string'
        ? ((data as Record<string, unknown>)[name] as string)
        : undefined
    const message = field('error') ?? (res.statusText || 'request failed')
    const code = field('code')
    const groupId = field('groupId')
    if (code === 'dm_exists' && groupId !== undefined) throw new DMExistsError(message, groupId)
    throw new ApiError(res.status, message, code)
  }
  return data as T
}

/**
 * POST /api/groups with a `dm` object. 409 codes: dm_exists (a DMExistsError carrying the group
 * id), dm_cooling_off, dm_conflict; 429 too_many_pending_dms; 404 recipient_not_found; 410
 * recipient_deleted; 400 bad_signature (the recipient's keys changed since they were shown) or
 * clock_skew.
 */
export async function createDM(req: CreateGroupRequest): Promise<CreateGroupResponse> {
  const res = await fetch('/api/groups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(req),
  })
  return handleJSON<CreateGroupResponse>(res)
}

/** One DM waiting for the caller to open, as GET /api/dms/incoming serves it. */
export interface IncomingDM {
  readonly groupId: string
  readonly senderUserId: string
  readonly requestId: string
  /** The caller's own keys as the sender signed them. */
  readonly recipientEd25519PublicKey: string
  readonly recipientX25519PublicKey: string
  readonly wrappedGroupKey: WireWrappedKey
  readonly admissionDay: string
  readonly admissionGrantRef: string
  readonly admissionSignature: string
}

/** GET /api/dms/incoming -- the first 100 DMs waiting, no cursor. */
export async function listIncomingDMs(): Promise<readonly IncomingDM[]> {
  const res = await fetch('/api/dms/incoming', { credentials: 'same-origin' })
  const data = await handleJSON<{ dms?: readonly IncomingDM[] }>(res)
  if (!Array.isArray(data.dms)) throw new ApiError(res.status, 'malformed response')
  return data.dms
}

const dmPath = (groupId: string, action: 'accept' | 'decline', requestId: string): string =>
  `/api/dms/${encodeURIComponent(groupId)}/${action}?requestId=${encodeURIComponent(requestId)}`

/** POST /api/dms/{gid}/accept?requestId=. 409: keys_changed, already_member, request_changed; 410 account_deleted. */
export async function acceptDM(groupId: string, requestId: string): Promise<void> {
  await handleJSON<unknown>(
    await fetch(dmPath(groupId, 'accept', requestId), { method: 'POST', credentials: 'same-origin' }),
  )
}

/** POST /api/dms/{gid}/decline?requestId=. */
export async function declineDM(groupId: string, requestId: string): Promise<void> {
  await handleJSON<unknown>(
    await fetch(dmPath(groupId, 'decline', requestId), { method: 'POST', credentials: 'same-origin' }),
  )
}
