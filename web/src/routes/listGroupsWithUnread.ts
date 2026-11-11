// The app shell's group list call (#145, #47): the groups with unread counts, fetched after any mark-read in
// flight has finished (for at most `maxWaitMs`), so a user who marks rows read and goes straight
// Back does not see a badge for them. The wait is capped because it holds the WHOLE list, and a
// mark-read that hangs must not hold Home with it; past the cap the counts may still include rows
// that are being marked, and the next refetch corrects them.

import type { ListGroupsResponse } from '@/lib/api/groups'

/** The longest the shell waits for marks in flight before it loads the list anyway. */
export const MARK_WAIT_CAP_MS = 3000

export async function listGroupsWithUnread(deps: {
  readonly settled: () => Promise<void>
  readonly listGroups: (opts: { readonly unread: true }) => Promise<ListGroupsResponse>
  readonly maxWaitMs?: number
}): Promise<ListGroupsResponse> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const cap = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, deps.maxWaitMs ?? MARK_WAIT_CAP_MS)
  })
  try {
    await Promise.race([deps.settled(), cap])
  } finally {
    clearTimeout(timer)
  }
  return deps.listGroups({ unread: true })
}
