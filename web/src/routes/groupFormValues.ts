// What the create-group form hands up. Kept out of the component file so it can be tested directly.

import type { GroupFormValues } from './CreateGroupFormStep'

export const DEFAULT_EXPIRATION_DAYS = 30

/** A public group is always Open (the server refuses anything else); a private one keeps the choice. */
export function revocationModeFor(
  visibility: 'private' | 'public',
  chosen: 'rotating' | 'open',
): 'rotating' | 'open' {
  return visibility === 'public' ? 'open' : chosen
}

/** What the form hands up on submit: the public-is-Open rule and the expiry default applied. */
export function buildGroupValues(f: {
  readonly visibility: 'private' | 'public'
  readonly name: string
  readonly description: string
  readonly revocationMode: 'rotating' | 'open'
  readonly neverExpires: boolean
}): GroupFormValues {
  return {
    visibility: f.visibility,
    name: f.name,
    description: f.description,
    revocationMode: revocationModeFor(f.visibility, f.revocationMode),
    expirationDays: f.neverExpires ? 0 : DEFAULT_EXPIRATION_DAYS,
  }
}
