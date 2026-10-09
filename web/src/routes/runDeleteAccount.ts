// The async body and the pure rules behind deleting the account -- issue #77.
// Same split as runLeaveGroup.ts: dependencies come in as arguments so it is
// unit-testable under vitest's node environment.
//
// The server refuses to delete an account that still belongs to a group, so
// this leaves every group first, each with its own signed demotion (that is
// the answer to #161's "who signs" for account deletion: the user does).
// Leaving is not undoable, so nothing is left until a read-only pass has
// shown that every group CAN be left, and the leaves that can fail for want of
// a signature run before the ones that cannot be undone.

import { ApiError } from '@/lib/api/auth'
import { isDeletedUser } from './memberLabel'
import { loadMembers, type LoadMembersDeps, type MembersView } from './runGroupMembers'
import {
  leavePlan,
  runLeave,
  type LeaveDeps,
  type LeavePlan,
  type LeaveResult,
} from './runLeaveGroup'

export interface AccountPlanEntry {
  readonly groupId: string
  readonly view: MembersView
  readonly plan: LeavePlan
  /**
   * Set on a needsSuccessor group where every other member's account was
   * deleted, so nobody can be promoted (#193): the fix is to remove them, not
   * to pick a successor. Absent means "not known to be", so an unresolved name
   * keeps the optimistic wording.
   */
  readonly noLiveSuccessor?: boolean
}

export type AccountPlanResult =
  | { readonly ok: true; readonly entries: readonly AccountPlanEntry[] }
  | { readonly ok: false; readonly kind: 'authRequired' | 'failed' }

// Each group costs a group read and at least one roster page, so an account in
// many groups would otherwise fire every request at once, and one throttled
// request fails the whole plan.
const PLAN_CONCURRENCY = 4

/** Like Promise.all(items.map(fn)), with at most `limit` calls in flight; result order matches items. */
async function mapWithLimit<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0
  const worker = async (): Promise<void> => {
    while (next < items.length) {
      const i = next++
      results[i] = await fn(items[i] as T)
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return results
}

export interface PlanDeps extends LoadMembersDeps {
  readonly userId: string
  /**
   * Best effort and never throws (see resolveUsernames); an id it leaves out is
   * treated as live. The page-lifetime cache means a name cached before the
   * account was deleted is also treated as live, so this narrows the mid-run
   * last_admin failure rather than guaranteeing it cannot happen.
   */
  readonly resolveUsernames: (ids: readonly string[]) => Promise<ReadonlyMap<string, string>>
}

/**
 * Reads every group's roster and works out what leaving it would do. Writes
 * nothing. Fails as a whole if any roster cannot be read: a plan that silently
 * skipped a group would let the delete run and then 409 on it.
 */
export async function planAccountDeletion(
  deps: PlanDeps,
  groupIds: readonly string[],
): Promise<AccountPlanResult> {
  const results = await mapWithLimit(groupIds, PLAN_CONCURRENCY, (id) => loadMembers(deps, id))
  const views: MembersView[] = []
  for (const result of results) {
    if (!result.ok) {
      // A group that has vanished since the list loaded is not a failure to
      // plan around: there is nothing left to leave.
      if (result.kind === 'notFound') {
        continue
      }
      return { ok: false, kind: result.kind === 'authRequired' ? 'authRequired' : 'failed' }
    }
    views.push(result.view)
  }
  // A group whose only other admins were deleted is a blocker (#77), but only
  // leavePlan can say so, and only once it knows which admins are deleted. So
  // resolve the other admins, and only those, in the groups the caller admins:
  // a roster-wide read would cost a request per member for nothing.
  const otherAdmins = views.flatMap((v) =>
    v.myRole === 'admin'
      ? v.members.filter((x) => x.role === 'admin' && x.userId !== deps.userId).map((x) => x.userId)
      : [],
  )
  const usernames = otherAdmins.length === 0 ? undefined : await deps.resolveUsernames(otherAdmins)
  const planned = views.map((view) => ({
    groupId: view.groupId,
    view,
    plan: leavePlan(view, deps.userId, usernames),
  }))
  // Only a group that already blocks needs to know whether anyone in it can be
  // promoted, so only its members are resolved (the other admins are cached).
  const candidates = [
    ...new Set(planned.flatMap((e) => (e.plan.kind === 'needsSuccessor' ? e.plan.candidates : []))),
  ]
  const candidateNames =
    candidates.length === 0 ? undefined : await deps.resolveUsernames(candidates)
  const entries: AccountPlanEntry[] = planned.map((e) =>
    e.plan.kind === 'needsSuccessor' &&
    e.plan.candidates.every((id) => isDeletedUser(id, candidateNames))
      ? { ...e, noLiveSuccessor: true }
      : e,
  )
  return { ok: true, entries }
}

/**
 * Groups that stop the deletion before anything is changed: the last admin of
 * a group that has other members (promote a successor first), and an
 * admin or ambassador whose own grant is not on record (they cannot sign the
 * demotion, and reloading will not fix that).
 */
export function deletionBlockers(
  entries: readonly AccountPlanEntry[],
): readonly AccountPlanEntry[] {
  return entries.filter(
    (e) =>
      e.plan.kind === 'needsSuccessor' ||
      (e.plan.kind === 'plain' && e.view.myRole !== 'member' && !e.view.myGrantSortKey),
  )
}

/** Why a group in deletionBlockers blocks, so the screen can say which fix applies. */
export function blockerReason(
  entry: AccountPlanEntry,
): 'needsSuccessor' | 'noSuccessor' | 'grantMissing' {
  if (entry.plan.kind !== 'needsSuccessor') {
    return 'grantMissing'
  }
  return entry.noLiveSuccessor === true ? 'noSuccessor' : 'needsSuccessor'
}

/** Groups whose only member is the caller: leaving them deletes them and their content. */
export function groupsThatWillBeDeleted(
  entries: readonly AccountPlanEntry[],
): readonly AccountPlanEntry[] {
  return entries.filter((e) => e.plan.kind === 'deletesGroup')
}

/**
 * The order the leaves run in: groups that need a signed demotion first, so a
 * browser that cannot sign (a fresh page load) fails before anything has been
 * left; plain leaves next; the groups the leave deletes last, because that is
 * the one loss that cannot be walked back.
 */
export function leaveOrder(entries: readonly AccountPlanEntry[]): readonly AccountPlanEntry[] {
  const rank = (e: AccountPlanEntry): number =>
    e.plan.kind === 'deletesGroup' ? 2 : e.view.myRole === 'member' ? 1 : 0
  return [...entries].sort((a, b) => rank(a) - rank(b))
}

export type DeleteAccountResult =
  | { readonly ok: true; readonly left: number }
  | { readonly ok: false; readonly kind: 'blocked'; readonly groupIds: readonly string[] }
  // One group could not be left. `left` groups already were; running this
  // again plans from what remains, so a retry resumes rather than restarts.
  | {
      readonly ok: false
      readonly kind: 'leaveFailed'
      readonly groupId: string
      readonly reason: Exclude<LeaveResult, { ok: true }>['kind']
      readonly left: number
    }
  // The groups changed between the plan the user confirmed and the one read
  // just before leaving (someone left, a role moved, a group appeared). Nothing
  // was changed; `entries` is the fresh plan to show for another confirmation.
  | {
      readonly ok: false
      readonly kind: 'planChanged'
      readonly entries: readonly AccountPlanEntry[]
    }
  // The groups could not be re-read to check the plan. Nothing was changed.
  | { readonly ok: false; readonly kind: 'replanFailed' }
  // The groups are left but the account still belongs to one: someone's
  // invite completed in between. Run again.
  | { readonly ok: false; readonly kind: 'stillMember'; readonly left: number }
  | { readonly ok: false; readonly kind: 'authRequired'; readonly left: number }
  // Network failure or 5xx on the final delete: it may or may not have committed.
  | { readonly ok: false; readonly kind: 'ambiguous'; readonly left: number }

export interface DeleteAccountDeps extends LeaveDeps {
  readonly deleteAccount: () => Promise<void>
}

export interface ConfirmedDeletionDeps extends DeleteAccountDeps {
  /** Reads and plans every group again, exactly as the first plan was made. */
  readonly replan: () => Promise<AccountPlanResult>
}

/**
 * What a confirmation is a confirmation OF: each group, what leaving it does,
 * and the caller's role and grant in it. Two plans with the same fingerprint
 * show the user the same thing.
 */
export function planFingerprint(entries: readonly AccountPlanEntry[]): string {
  return entries
    .map((e) => `${e.groupId}|${e.plan.kind}|${e.view.myRole}|${e.view.myGrantSortKey ?? ''}`)
    .sort()
    .join('\n')
}

/**
 * Runs the deletion the user confirmed, but only if it is still the deletion
 * they were shown. The server deletes a group whenever the caller is its last
 * member, whatever the client planned, so a plan made minutes ago can turn a
 * "you will leave" into a permanent loss (the other member left meanwhile).
 * The groups are read again first; any difference refuses with the fresh plan
 * and changes nothing. A match runs on the fresh entries, which carry the same
 * role and grant the fingerprint compared, so which set is used makes no
 * difference to what is sent. This narrows the window to one round of reads;
 * closing it fully needs the leave endpoint to refuse to delete a group the
 * client did not expect to.
 */
export async function runConfirmedDeletion(
  deps: ConfirmedDeletionDeps,
  shown: readonly AccountPlanEntry[],
): Promise<DeleteAccountResult> {
  const fresh = await deps.replan()
  if (!fresh.ok) {
    return fresh.kind === 'authRequired'
      ? { ok: false, kind: 'authRequired', left: 0 }
      : { ok: false, kind: 'replanFailed' }
  }
  if (planFingerprint(fresh.entries) !== planFingerprint(shown)) {
    return { ok: false, kind: 'planChanged', entries: fresh.entries }
  }
  return runDeleteAccount(deps, fresh.entries)
}

/** Leaves every group in `entries`, then deletes the account. */
export async function runDeleteAccount(
  deps: DeleteAccountDeps,
  entries: readonly AccountPlanEntry[],
): Promise<DeleteAccountResult> {
  const blocked = deletionBlockers(entries)
  if (blocked.length > 0) {
    return { ok: false, kind: 'blocked', groupIds: blocked.map((e) => e.groupId) }
  }

  let left = 0
  for (const entry of leaveOrder(entries)) {
    const outcome = await runLeave(deps, entry.view, entry.plan.kind)
    // Already gone from this group counts as left.
    if (outcome.ok || outcome.kind === 'notFound') {
      left++
      continue
    }
    if (outcome.kind === 'authRequired') {
      return { ok: false, kind: 'authRequired', left }
    }
    return { ok: false, kind: 'leaveFailed', groupId: entry.groupId, reason: outcome.kind, left }
  }

  try {
    await deps.deleteAccount()
    return { ok: true, left }
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 409 && err.code === 'still_member') {
        return { ok: false, kind: 'stillMember', left }
      }
      if (err.status === 401) {
        return { ok: false, kind: 'authRequired', left }
      }
    }
    return { ok: false, kind: 'ambiguous', left }
  }
}

const LEAVE_REASONS: Record<
  Extract<DeleteAccountResult, { kind: 'leaveFailed' }>['reason'],
  string
> = {
  lastAdmin: 'is one you are the last admin of, so promote a successor there first',
  stale: 'changed while this was running',
  authRequired: 'could not be left because your session expired',
  coldKeys: 'needs this browser to sign your leaving, so log in again first',
  grantMissing: "doesn't have your own role on record, so it can't be left from here",
  rotationInProgress: 'has a key rotation still running, so wait for it to finish and try again',
  noGroupKey: "needs this browser to hold the group's key to re-key it for your leaving",
  noHolder:
    "has no other admin who can take its new key (none is up to date, or their keys or invitations did not check out), so it can't be left yet",
  cannotCheck: "couldn't be checked: its admins' keys could not be read",
  notFound: 'no longer lists you',
  ambiguous: "couldn't be confirmed",
}

/**
 * The message for a failed run. `groupLabel` names a group by id. Every
 * message says how many groups were already left, because those are done.
 */
export function deleteFailureMessage(
  result: Exclude<DeleteAccountResult, { ok: true }>,
  groupLabel: (groupId: string) => string,
): string {
  const progress = (left: number): string =>
    left === 0
      ? 'Nothing was changed.'
      : `You have already left ${left} ${left === 1 ? 'group' : 'groups'}; running this again picks up from there.`
  switch (result.kind) {
    case 'blocked':
      return `You can't delete your account yet: ${result.groupIds.map(groupLabel).join(', ')} need${result.groupIds.length === 1 ? 's' : ''} your attention first. Nothing was changed.`
    case 'leaveFailed':
      return `${groupLabel(result.groupId)} ${LEAVE_REASONS[result.reason]}. ${progress(result.left)}`
    case 'planChanged':
      return 'Your groups changed while this page was open. Check the list and confirm again. Nothing was changed.'
    case 'replanFailed':
      return "Couldn't re-check your groups before deleting, so nothing was changed. Try again."
    case 'stillMember':
      return `You still belong to a group, probably from an invite that just completed. ${progress(result.left)} Try again.`
    case 'authRequired':
      return `Your session has expired. Log in again and retry. ${progress(result.left)}`
    case 'ambiguous':
      return `We couldn't confirm whether your account was deleted. ${progress(result.left)} Try logging in before running this again.`
  }
}
