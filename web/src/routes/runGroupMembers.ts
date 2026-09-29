// The async bodies behind GroupMembersScreen -- issue #37. Plain functions
// that take their network/worker calls as arguments, the same split
// runGroupSettings.ts makes from its own screen, so this is unit-testable
// under vitest's node environment with no jsdom or real worker.

import { ApiError } from '@/lib/api/auth'
import type {
  ChangeMemberRoleRequest,
  GroupDetail,
  ListMembersResponse,
  MemberEntry,
  MemberRole,
} from '@/lib/api/groups'
import { isLiveKeysError } from './runListGroups'

/** The roster plus what the caller needs to act on it. */
export interface MembersView {
  readonly groupId: string
  readonly members: readonly MemberEntry[]
  /** The caller's own role; anything but 'admin' gets a read-only roster. */
  readonly myRole: GroupDetail['role']
  /** The grant a role change must be signed on top of; absent for a non-admin. */
  readonly myGrantSortKey: string | undefined
}

export interface LoadMembersDeps {
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  readonly listMembers: (groupId: string, cursor?: string) => Promise<ListMembersResponse>
}

export type LoadMembersResult =
  | { readonly ok: true; readonly view: MembersView }
  | { readonly ok: false; readonly kind: 'notFound' | 'authRequired' | 'failed' }

// A roster this deep means the server is not honoring nextCursor's contract;
// stop rather than loop forever.
const MAX_MEMBER_PAGES = 100

/** Reads the group and every page of its roster. Never throws. */
export async function loadMembers(
  deps: LoadMembersDeps,
  groupId: string,
): Promise<LoadMembersResult> {
  try {
    const [detail, members] = await Promise.all([
      deps.getGroup(groupId),
      listAllMembers(deps, groupId),
    ])
    // Non-members of a public group can read the detail but not the roster
    // (the roster call 404s above), so reaching here means the caller is a member.
    return {
      ok: true,
      view: { groupId, members, myRole: detail.role, myGrantSortKey: detail.myGrantSortKey },
    }
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return { ok: false, kind: 'notFound' }
    }
    if (err instanceof ApiError && err.status === 401) {
      return { ok: false, kind: 'authRequired' }
    }
    return { ok: false, kind: 'failed' }
  }
}

async function listAllMembers(deps: LoadMembersDeps, groupId: string): Promise<MemberEntry[]> {
  const all: MemberEntry[] = []
  let cursor: string | undefined
  for (let page = 0; page < MAX_MEMBER_PAGES; page++) {
    const res = await deps.listMembers(groupId, cursor)
    all.push(...res.members)
    if (!res.nextCursor) {
      return all
    }
    cursor = res.nextCursor
  }
  throw new Error('roster pagination did not terminate')
}

export interface ChangeRoleDeps {
  readonly signRoleGrant: (req: {
    readonly userId: string
    readonly groupId: string
    readonly subjectUserId: string
    readonly role: MemberRole
    readonly grantorGrantRef: string
  }) => Promise<{ grantSortKey: string; signature: string }>
  readonly changeMemberRole: (
    groupId: string,
    userId: string,
    req: ChangeMemberRoleRequest,
  ) => Promise<{ role: MemberRole; grantSortKey: string }>
  /** The signed-in user's own id. */
  readonly userId: string
}

export type ChangeRoleResult =
  | { readonly ok: true }
  // A 409 that means the roster or the caller's own standing moved under
  // them. Reload and let the user decide again; never resend as-is.
  | { readonly ok: false; readonly kind: 'stale' }
  | { readonly ok: false; readonly kind: 'forbidden' | 'authRequired' | 'coldKeys' | 'notFound' }
  // A 4xx validation failure, with the server's own message.
  | { readonly ok: false; readonly kind: 'rejected'; readonly message: string }
  // Network failure or 5xx: the change may or may not have committed.
  | { readonly ok: false; readonly kind: 'ambiguous' }

const STALE_CODES = new Set([
  'grantor_ref_stale',
  'grantor_changed',
  'subject_role_changed',
  'conflict_retry',
  'grantor_grant_missing',
])

// A collision on a fresh random address is vanishingly rare; one re-sign is
// plenty and a second collision is reported instead of looped on.
const MAX_SIGN_ATTEMPTS = 2

/**
 * Signs a role grant under the caller's current grant and submits it. A
 * 'grant_key_taken' conflict re-signs with a new address (the old signature
 * is bound to the taken one); every other 409 is reported as 'stale'.
 */
export async function changeRole(
  deps: ChangeRoleDeps,
  view: MembersView,
  subjectUserId: string,
  role: MemberRole,
): Promise<ChangeRoleResult> {
  if (view.myRole !== 'admin' || view.myGrantSortKey === undefined || view.myGrantSortKey === '') {
    return { ok: false, kind: 'forbidden' }
  }
  const grantorGrantRef = view.myGrantSortKey

  for (let attempt = 1; attempt <= MAX_SIGN_ATTEMPTS; attempt++) {
    let signed: { grantSortKey: string; signature: string }
    try {
      signed = await deps.signRoleGrant({
        userId: deps.userId,
        groupId: view.groupId,
        subjectUserId,
        role,
        grantorGrantRef,
      })
    } catch (err) {
      // A worker call, not a request: nothing was sent.
      return isLiveKeysError(err)
        ? { ok: false, kind: 'coldKeys' }
        : { ok: false, kind: 'rejected', message: "Couldn't sign this change. Try again." }
    }

    try {
      await deps.changeMemberRole(view.groupId, subjectUserId, {
        role,
        grantSortKey: signed.grantSortKey,
        grantorGrantRef,
        signature: signed.signature,
      })
      return { ok: true }
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 409 && err.code === 'grant_key_taken' && attempt < MAX_SIGN_ATTEMPTS) {
          continue
        }
        if (err.status === 409) {
          return err.code !== undefined && STALE_CODES.has(err.code)
            ? { ok: false, kind: 'stale' }
            : { ok: false, kind: 'rejected', message: err.message }
        }
        if (err.status === 401) {
          return { ok: false, kind: 'authRequired' }
        }
        if (err.status === 403) {
          return { ok: false, kind: 'forbidden' }
        }
        if (err.status === 404) {
          return { ok: false, kind: 'notFound' }
        }
        if (err.status < 500) {
          return { ok: false, kind: 'rejected', message: err.message }
        }
      }
      return { ok: false, kind: 'ambiguous' }
    }
  }
  return { ok: false, kind: 'ambiguous' }
}
