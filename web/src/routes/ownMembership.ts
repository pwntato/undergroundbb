// The caller's own membership in a group, in the shape runCompleteInvites
// needs: lifted out of LoginScreen so the group-list branches can be tested.

import type { GroupDetail, ListGroupsResponse } from '@/lib/api/groups'
import type { OwnMembershipForCompletion } from './runCompleteInvites'

export interface OwnMembershipDeps {
  readonly listGroups: () => Promise<ListGroupsResponse>
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
}

/**
 * Returns a getOwnMembership for runCompleteInvites. The group list is fetched
 * once and reused across every pending invite, rather than once per invite.
 * A group the caller is not in, or one whose entry carries no wrapped key, is
 * null (they are no longer a member). A public group's entry carries the wrap
 * like a private one's, so its invites complete too.
 */
export function makeGetOwnMembership(
  deps: OwnMembershipDeps,
): (groupId: string) => Promise<OwnMembershipForCompletion | null> {
  let ownGroups: Promise<ListGroupsResponse> | undefined
  return async (groupId) => {
    ownGroups ??= deps.listGroups()
    const { groups } = await ownGroups
    const entry = groups.find((g) => g.groupId === groupId)
    if (entry === undefined || entry.wrappedGroupKey === undefined) {
      return null
    }
    // The admission signs the inviter's own current grant (#178), which only
    // the group detail reports.
    const detail = await deps.getGroup(groupId)
    if (detail.myGrantSortKey === undefined) {
      throw new Error('your own grant is not on record for this group')
    }
    return {
      generation: entry.generation,
      grantSortKey: detail.myGrantSortKey,
      wrappedGroupKey: entry.wrappedGroupKey,
    }
  }
}
