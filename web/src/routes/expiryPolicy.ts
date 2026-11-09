// The deployment's message-expiration policy as the group screens use it (#78): whether "never expire"
// may be offered at all, and the number of days a new group starts with. Both come from GET /api/config
// (the server enforces the same rule; this only stops the UI offering what would be refused).

import { MAX_EXPIRATION_DAYS } from './groupSettingsForm'

export interface ExpiryPolicy {
  readonly allowNeverExpire: boolean
  readonly defaultDays: number
}

/** Used until the config arrives and when it cannot be read: no permanent archives, 30 days. */
export const SAFE_EXPIRY_POLICY: ExpiryPolicy = { allowNeverExpire: false, defaultDays: 30 }

/** Reads the policy out of a /api/config body, falling back to the safe value for anything unexpected. */
export function expiryPolicyOf(config: unknown): ExpiryPolicy {
  if (typeof config !== 'object' || config === null) return SAFE_EXPIRY_POLICY
  const c = config as { allowGroupExpirationOff?: unknown; defaultExpirationDays?: unknown }
  const days = c.defaultExpirationDays
  return {
    allowNeverExpire: c.allowGroupExpirationOff === true,
    defaultDays:
      typeof days === 'number' && Number.isInteger(days) && days >= 1 && days <= MAX_EXPIRATION_DAYS
        ? days
        : SAFE_EXPIRY_POLICY.defaultDays,
  }
}

/**
 * The expirationDays to send: 0 ("never") only when the box is ticked AND the deployment allows it,
 * otherwise `days`. A stale tick (a group that was never-expire, on a deployment that now forbids it)
 * therefore cannot produce a request the server would refuse.
 */
export function chosenExpirationDays(opts: {
  readonly neverExpires: boolean
  readonly policy: ExpiryPolicy
  readonly days: number
}): number {
  return opts.neverExpires && opts.policy.allowNeverExpire ? 0 : opts.days
}
