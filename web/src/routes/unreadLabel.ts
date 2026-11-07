/**
 * The unread badge text for a group (#145): nothing for none, the number, or the number with a
 * plus when the server says it is only a lower bound (more than 99, or its read hit a limit).
 */
export function unreadLabel(unread: number, unreadMore: boolean): string | null {
  if (unread <= 0 && !unreadMore) return null
  return unreadMore ? `${unread}+` : String(unread)
}
