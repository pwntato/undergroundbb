// The roster has ids only until the users projection (GET /api/users/:id)
// exists; kept out of the panel so that file exports only its component.

/** A short stand-in for a username: the first block of the member's uuid. */
export function memberLabel(userId: string): string {
  return userId.split('-')[0] ?? userId
}
