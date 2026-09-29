// The async body and the pure rules behind leaving a group -- issue #66. Same
// split as runGroupMembers.ts: dependencies come in as arguments so it is
// unit-testable under vitest's node environment.

import { ApiError } from '@/lib/api/auth'
import type { MembersView } from './runGroupMembers'

/** What leaving means for this caller, from the roster they are looking at. */
export type LeavePlan =
  /** Only member: leaving deletes the group. */
  | { readonly kind: 'deletesGroup' }
  /** Last Admin with others remaining: must name a successor first. */
  | { readonly kind: 'needsSuccessor'; readonly candidates: readonly string[] }
  | { readonly kind: 'plain' }

/**
 * Computed from the loaded roster, so it can be stale; the server re-checks
 * and answers 409 last_admin if this plan was optimistic.
 */
export function leavePlan(view: MembersView, userId: string): LeavePlan {
  const others = view.members.filter((m) => m.userId !== userId)
  if (others.length === 0) {
    return { kind: 'deletesGroup' }
  }
  if (view.myRole === 'admin' && !others.some((m) => m.role === 'admin')) {
    return { kind: 'needsSuccessor', candidates: others.map((m) => m.userId) }
  }
  return { kind: 'plain' }
}

export type LeaveResult =
  | { readonly ok: true; readonly groupDeleted: boolean }
  // The plan was stale: the roster or the caller's role moved. Reload.
  | { readonly ok: false; readonly kind: 'lastAdmin' | 'stale' }
  | { readonly ok: false; readonly kind: 'authRequired' }
  // Not a member any more (already left, or removed): nothing to leave.
  | { readonly ok: false; readonly kind: 'notFound' }
  // Network failure or 5xx: the leave may or may not have committed.
  | { readonly ok: false; readonly kind: 'ambiguous' }

export async function runLeave(
  deps: { readonly leaveGroup: (groupId: string) => Promise<{ groupDeleted: boolean }> },
  groupId: string,
): Promise<LeaveResult> {
  try {
    const res = await deps.leaveGroup(groupId)
    return { ok: true, groupDeleted: res.groupDeleted }
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 409) {
        return { ok: false, kind: err.code === 'last_admin' ? 'lastAdmin' : 'stale' }
      }
      if (err.status === 401) {
        return { ok: false, kind: 'authRequired' }
      }
      if (err.status === 404) {
        return { ok: false, kind: 'notFound' }
      }
    }
    return { ok: false, kind: 'ambiguous' }
  }
}

const LEAVE_ERRORS: Record<Exclude<LeaveResult, { ok: true }>['kind'], string> = {
  lastAdmin:
    'You are the last admin, so you cannot leave yet. The latest roster is shown; choose a successor.',
  stale: 'The group changed while you were working, so nothing was saved. Try again.',
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'You are no longer a member of this group.',
  ambiguous: "We couldn't confirm whether you left. Check your group list before trying again.",
}

/**
 * The message for a failed leave. When `promotedName` is set the successor's
 * promotion had already committed, so "nothing was saved" would be false:
 * they are an admin now and a retry is a plain leave.
 */
export function leaveFailureMessage(
  kind: Exclude<LeaveResult, { ok: true }>['kind'],
  promotedName?: string,
): string {
  if (
    promotedName !== undefined &&
    (kind === 'stale' || kind === 'ambiguous' || kind === 'lastAdmin')
  ) {
    return `${promotedName} is now an admin, but leaving didn't go through. Try Leave again.`
  }
  return LEAVE_ERRORS[kind]
}
