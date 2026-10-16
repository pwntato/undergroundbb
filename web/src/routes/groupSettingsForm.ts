// Constants and validation for the group settings form -- issue #36. Kept
// out of GroupSettingsPanel.tsx so that file exports only its component
// (fast refresh), and so the validation can be unit-tested directly.

import { groupTextLengthError } from './groupTextLimits'
import type { SettingsForm } from './runGroupSettings'

export const MAX_EXPIRATION_DAYS = 3650
export const FALLBACK_EXPIRATION_DAYS = 30

/**
 * What removing a member does in each mode. `memberCap` is the deployment's limit for this
 * group (GroupDetail.memberCap), not a fixed number: it is read from the server so the text
 * cannot disagree with what the server enforces.
 */
export function revocationText(mode: 'rotating' | 'open', memberCap: number): string {
  if (mode === 'open') {
    return 'Open: removing a member only revokes their access. The group is never re-keyed, so a removed member keeps the group key and can still decrypt anything they get hold of. There is no member cap.'
  }
  const cap = memberCap > 0 ? ` Capped at ${memberCap.toLocaleString('en-US')} members.` : ''
  return `Rotating: removing a member re-keys the group. A removed member keeps what they've already read but can't read new posts.${cap}`
}

/** Validates the form; returns the error to show, or null if it can be submitted. */
export function validateSettingsForm(form: SettingsForm): string | null {
  if (form.name.trim() === '') {
    return 'Group name is required.'
  }
  const textError = groupTextLengthError(form.name, form.description)
  if (textError !== null) {
    return textError
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
