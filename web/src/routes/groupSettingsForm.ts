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

/** Validates the form; returns the error to show, or null if it can be submitted. */
export function validateSettingsForm(form: SettingsForm): string | null {
  if (form.name.trim() === '') {
    return 'Group name is required.'
  }
  if (form.name.length > MAX_NAME_LENGTH) {
    return `Group name must be ${String(MAX_NAME_LENGTH)} characters or fewer.`
  }
  if (form.description.length > MAX_DESCRIPTION_LENGTH) {
    return `Description must be ${String(MAX_DESCRIPTION_LENGTH)} characters or fewer.`
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
