/**
 * The unread badge text for a group (#145): nothing for none, the number, or the number with a
 * plus when the server says it is only a lower bound (more than 99, or its read hit a limit).
 * Never a badge for zero: a count of 0 with "more" would be a false alarm on every group.
 */
export function unreadLabel(unread: number | undefined, unreadMore: boolean | undefined): string | null {
  if (unread === undefined || unread <= 0) return null
  return unreadMore ? `${unread}+` : String(unread)
}

/** What a screen reader says for the badge. */
export function unreadAriaLabel(label: string, unread: number): string {
  return `${label} unread ${unread === 1 ? 'notification' : 'notifications'}`
}
