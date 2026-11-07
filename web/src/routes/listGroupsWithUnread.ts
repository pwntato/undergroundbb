// Home's group list call (#145): the groups with unread counts, fetched only after any mark-read in
// flight has finished, so a user who marks rows read and goes straight Back does not see a badge
// for them.

import type { ListGroupsResponse } from '@/lib/api/groups'

export async function listGroupsWithUnread(deps: {
  readonly settled: () => Promise<void>
  readonly listGroups: (opts: { readonly unread: true }) => Promise<ListGroupsResponse>
}): Promise<ListGroupsResponse> {
  await deps.settled()
  return deps.listGroups({ unread: true })
}
