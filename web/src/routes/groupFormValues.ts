// What the create-group form hands up. Kept out of the component file so it can be tested directly.

import { chosenExpirationDays, type ExpiryPolicy } from './expiryPolicy'

export interface GroupFormValues {
  readonly visibility: 'private' | 'public'
  readonly name: string
  readonly description: string
  readonly revocationMode: 'rotating' | 'open'
  readonly expirationDays: number
}

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
  readonly policy: ExpiryPolicy
}): GroupFormValues {
  return {
    visibility: f.visibility,
    name: f.name,
    description: f.description,
    revocationMode: revocationModeFor(f.visibility, f.revocationMode),
    expirationDays: chosenExpirationDays({
      neverExpires: f.neverExpires,
      policy: f.policy,
      days: f.policy.defaultDays,
    }),
  }
}
