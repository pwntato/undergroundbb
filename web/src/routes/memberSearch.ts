import { memberLabel } from './memberLabel'

// Member search (#76), done in the browser over the roster the screen has
// already loaded. There is deliberately no server endpoint: a search that
// reaches beyond a group's own roster would let any signed-in user enumerate
// usernames, and one that stays inside the caller's groups would read every
// member of every group per keystroke (up to 10,000 per group).

/**
 * The members whose displayed name starts with `query`, ignoring case and
 * surrounding space, in their original order. An empty query matches everyone.
 * The name compared is the one the row shows (`memberLabel`): the username,
 * the short id while it loads, or "deleted user", so every visible row can be
 * found by typing what is on it. Members in `keep` stay listed whatever they
 * match, because something is open on their row.
 */
export function filterMembersByQuery<T extends { readonly userId: string }>(
  members: readonly T[],
  usernames: ReadonlyMap<string, string>,
  query: string,
  keep: ReadonlySet<string> = new Set(),
): readonly T[] {
  const q = query.trim().toLowerCase()
  if (q === '') {
    return members
  }
  return members.filter(
    (m) => keep.has(m.userId) || memberLabel(m.userId, usernames).toLowerCase().startsWith(q),
  )
}
