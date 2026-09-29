// The async bodies behind InvitesScreen -- issue #41. Plain functions that
// take their network calls as arguments, the same split runGroupMembers.ts
// makes from its own screen, so they are unit-testable under vitest's node
// environment.

import { ApiError } from '@/lib/api/auth'
import type { ReceivedInvitesResponse, SentInvitesResponse } from '@/lib/api/invites'

export interface InvitesView {
  readonly sent: SentInvitesResponse['invites']
  readonly received: ReceivedInvitesResponse['invites']
}

export interface LoadInvitesDeps {
  readonly sentInvites: () => Promise<SentInvitesResponse>
  readonly receivedInvites: () => Promise<ReceivedInvitesResponse>
}

export type LoadInvitesResult =
  | { readonly ok: true; readonly view: InvitesView }
  | { readonly ok: false; readonly kind: 'authRequired' | 'failed' }

/** Reads both lists. Never throws; either list failing fails the load, so neither is shown half-stale. */
export async function loadInvites(deps: LoadInvitesDeps): Promise<LoadInvitesResult> {
  try {
    const [sent, received] = await Promise.all([deps.sentInvites(), deps.receivedInvites()])
    return { ok: true, view: { sent: sent.invites, received: received.invites } }
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) {
      return { ok: false, kind: 'authRequired' }
    }
    return { ok: false, kind: 'failed' }
  }
}

export interface RevokeDeps {
  readonly revokeInvite: (inviteId: string) => Promise<void>
}

export type RevokeResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly kind: 'accepted' | 'gone' | 'authRequired' | 'failed' }

/**
 * Revokes one pending invite. 'accepted' (409 invite_already_accepted) means
 * an invitee got there first; 'gone' (404) means it is already revoked or
 * expired. Both are states the reloaded list will show correctly.
 */
export async function revokePending(deps: RevokeDeps, inviteId: string): Promise<RevokeResult> {
  try {
    await deps.revokeInvite(inviteId)
    return { ok: true }
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 409 && err.code === 'invite_already_accepted') {
        return { ok: false, kind: 'accepted' }
      }
      if (err.status === 404) {
        return { ok: false, kind: 'gone' }
      }
      if (err.status === 401) {
        return { ok: false, kind: 'authRequired' }
      }
    }
    return { ok: false, kind: 'failed' }
  }
}
