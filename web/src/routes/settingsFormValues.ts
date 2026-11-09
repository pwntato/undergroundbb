import { chosenExpirationDays, effectivePolicy, type ExpiryPolicy } from './expiryPolicy'
import type { SettingsForm } from './runGroupSettings'

/**
 * The settings form as submitted. 0 ("never expire") comes only from the checkbox, and only where the
 * deployment allows it (#78); an empty or zero days field becomes NaN so validation refuses it, rather
 * than silently disabling expiry.
 */
export function settingsFormOf(f: {
  readonly name: string
  readonly description: string
  readonly neverExpires: boolean
  readonly days: string
  readonly policy: ExpiryPolicy
  /** The group's stored expirationDays (0 = never): while the policy is unknown a never-expire group keeps it. */
  readonly currentDays: number
}): SettingsForm {
  return {
    name: f.name,
    description: f.description,
    expirationDays: chosenExpirationDays({
      neverExpires: f.neverExpires,
      policy: effectivePolicy(f.policy, f.currentDays),
      days: Number(f.days) >= 1 ? Number(f.days) : Number.NaN,
    }),
  }
}

/** The days field's starting text: the group's own number, or the deployment's default for a never-expire group. */
export function startingDays(expirationDays: number, policy: ExpiryPolicy): string {
  return String(expirationDays === 0 ? policy.defaultDays : expirationDays)
}
