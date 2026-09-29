/**
 * How a user is shown on the roster and invite rows: their username when the
 * users projection (GET /api/users/:id) has been read, otherwise the first
 * block of their uuid so a row is never blank while it loads or if the read
 * fails. Kept out of the panels so those files export only components.
 */
export function memberLabel(userId: string, usernames?: ReadonlyMap<string, string>): string {
  return usernames?.get(userId) ?? userId.split('-')[0] ?? userId
}

/** Monospace only for the uuid-fragment fallback, so an unresolved row is visibly so. */
export function unresolvedClass(userId: string, usernames?: ReadonlyMap<string, string>): string {
  return usernames?.has(userId) === true ? '' : 'font-mono'
}
