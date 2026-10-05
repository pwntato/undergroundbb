/** What a tombstoned account is called wherever its id would otherwise be shown (#77). */
export const DELETED_USER_LABEL = 'deleted user'

/**
 * How a user is shown on the roster and invite rows: their username when the
 * users projection (GET /api/users/:id) has been read, otherwise the first
 * block of their uuid so a row is never blank while it loads or if the read
 * fails. Kept out of the panels so those files export only components.
 */
export function memberLabel(userId: string, usernames?: ReadonlyMap<string, string>): string {
  const username = usernames?.get(userId)
  // An empty username is a deleted account (see resolveUsernames); a real
  // username is never empty.
  if (username === '') {
    return DELETED_USER_LABEL
  }
  return username ?? userId.split('-')[0] ?? userId
}

/** Monospace only for the uuid-fragment fallback, so an unresolved row is visibly so. */
export function unresolvedClass(userId: string, usernames?: ReadonlyMap<string, string>): string {
  return usernames?.has(userId) === true ? '' : 'font-mono'
}

/** Whether the user's account was deleted (#77); false while their name is unresolved. */
export function isDeletedUser(userId: string, usernames?: ReadonlyMap<string, string>): boolean {
  return usernames?.get(userId) === ''
}
