// Constants and validation for the group settings form -- issue #36. Kept
// out of GroupSettingsPanel.tsx so that file exports only its component
// (fast refresh), and so the validation can be unit-tested directly.

import type { SettingsForm } from './runGroupSettings'

export const MAX_EXPIRATION_DAYS = 3650
export const FALLBACK_EXPIRATION_DAYS = 30
const MAX_NAME_LENGTH = 200
const MAX_DESCRIPTION_LENGTH = 2000

export const REVOCATION_TEXT = {
  rotating:
    "Rotating: removing a member re-keys the group. A removed member keeps what they've already read but can't read new posts. Capped at 1,000 members.",
  open: 'Open: removing a member only revokes their access. The group is never re-keyed, so a removed member keeps the group key and can still decrypt anything they get hold of. There is no member cap.',
} as const

// The server bounds public names and descriptions in UTF-8 bytes (Go's len),
// not characters, so this counts bytes too: 150 accented or CJK characters
// pass a UTF-16 length check and are then rejected server-side (PR #151
// review).
const utf8Length = (text: string): number => new TextEncoder().encode(text).length

/** Validates the form; returns the error to show, or null if it can be submitted. */
export function validateSettingsForm(form: SettingsForm): string | null {
  if (form.name.trim() === '') {
    return 'Group name is required.'
  }
  if (utf8Length(form.name) > MAX_NAME_LENGTH) {
    return `Group name is too long. The limit is ${String(MAX_NAME_LENGTH)} bytes, and accented or non-Latin characters take more than one.`
  }
  if (utf8Length(form.description) > MAX_DESCRIPTION_LENGTH) {
    return `Description is too long. The limit is ${String(MAX_DESCRIPTION_LENGTH)} bytes, and accented or non-Latin characters take more than one.`
  }
  if (
    !Number.isInteger(form.expirationDays) ||
    form.expirationDays < 0 ||
    form.expirationDays > MAX_EXPIRATION_DAYS
  ) {
    return `Message expiration must be a whole number of days from 1 to ${String(MAX_EXPIRATION_DAYS)}.`
  }
  return null
}
