// Member search (#76), done in the browser over the roster the screen has
// already loaded. There is deliberately no server endpoint: a search that
// reaches beyond a group's own roster would let any signed-in user enumerate
// usernames, and one that stays inside the caller's groups would read every
// member of every group per keystroke (up to 10,000 per group).

/**
 * The members whose username starts with `query`, ignoring case and
 * surrounding space, in their original order. An empty query matches everyone.
 * Members whose username has not loaded yet, or whose account was deleted
 * (empty username), match nothing once a query is typed, because there is no
 * name to compare.
 */
export function filterMembersByQuery<T extends { readonly userId: string }>(
  members: readonly T[],
  usernames: ReadonlyMap<string, string>,
  query: string,
): readonly T[] {
  const q = query.trim().toLowerCase()
  if (q === '') {
    return members
  }
  return members.filter((m) => (usernames.get(m.userId) ?? '').toLowerCase().startsWith(q))
}
