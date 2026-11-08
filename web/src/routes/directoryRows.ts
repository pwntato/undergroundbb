// What the directory shows beside each public group (#71): whether the caller is already in it, has a
// request waiting, or was declined. Decided here, not in the panel, so it tests without a DOM.

import type { DirectoryEntry } from '@/lib/api/directory'
import type { MyJoinRequest } from '@/lib/api/joinRequests'

export type DirectoryStatus =
  | { readonly kind: 'member' }
  | { readonly kind: 'pending' }
  | { readonly kind: 'declined'; readonly retryAfter: string | undefined }
  | { readonly kind: 'available' }

export interface DirectoryRow {
  readonly entry: DirectoryEntry
  readonly status: DirectoryStatus
  /** The first block of the group id: what tells two groups with one name apart. */
  readonly shortId: string
}

/** A description cut to `max` characters on a word boundary where there is one, with an ellipsis. */
export function snippet(text: string | undefined, max = 140): string {
  if (text === undefined) return ''
  const t = text.trim()
  if (t.length <= max) return t
  const cut = t.slice(0, max)
  const space = cut.lastIndexOf(' ')
  return `${(space > max / 2 ? cut.slice(0, space) : cut).trimEnd()}…`
}

export function directoryRows(
  entries: readonly DirectoryEntry[],
  memberOf: ReadonlySet<string>,
  requests: readonly MyJoinRequest[],
): DirectoryRow[] {
  const byGroup = new Map(requests.map((r) => [r.groupId, r]))
  return entries.map((entry) => {
    let status: DirectoryStatus = { kind: 'available' }
    const req = byGroup.get(entry.groupId)
    // Membership wins: a leftover request row never hides that the caller is already in.
    if (memberOf.has(entry.groupId)) status = { kind: 'member' }
    else if (req?.status === 'pending') status = { kind: 'pending' }
    else if (req?.status === 'denied') status = { kind: 'declined', retryAfter: req.retryAfter }
    return { entry, status, shortId: entry.groupId.split('-')[0] ?? entry.groupId }
  })
}
