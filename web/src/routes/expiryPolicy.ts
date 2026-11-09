// The deployment's message-expiration policy as the group screens use it (#78): whether "never expire"
// may be offered at all, and the number of days a new group starts with. Both come from GET /api/config
// (the server enforces the same rule; this only stops the UI offering what would be refused).

import { MAX_EXPIRATION_DAYS } from './groupSettingsForm'

export interface ExpiryPolicy {
  /** False until /api/config has answered, and for good if it cannot be read. */
  readonly known: boolean
  readonly allowNeverExpire: boolean
  readonly defaultDays: number
}

/**
 * Used until the config arrives and when it cannot be read: nothing permanent is OFFERED, and new groups
 * start at 30 days. It is not a statement that the deployment forbids never-expire: see
 * `neverExpireAllowed` for what an existing group is saved as while the policy is unknown.
 */
export const SAFE_EXPIRY_POLICY: ExpiryPolicy = {
  known: false,
  allowNeverExpire: false,
  defaultDays: 30,
}

/** Reads the policy out of a /api/config body, falling back to the safe value for anything unexpected. */
export function expiryPolicyOf(config: unknown): ExpiryPolicy {
  if (typeof config !== 'object' || config === null) return SAFE_EXPIRY_POLICY
  const c = config as { allowGroupExpirationOff?: unknown; defaultExpirationDays?: unknown }
  const days = c.defaultExpirationDays
  return {
    known: true,
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

/**
 * Whether the settings screen treats never-expire as allowed for a group whose policy is `current` days
 * (0 = never). Where the deployment's answer is known, that answer. While it is not, a group that is
 * already never-expire keeps it, so a rename made before the config arrives (or after it failed to load)
 * cannot silently switch the group to expiring; the server stays the authority and refuses it if the
 * deployment really forbids it. A group that already expires is not offered the option until it is known.
 */
export function neverExpireAllowed(policy: ExpiryPolicy, current: number): boolean {
  return policy.known ? policy.allowNeverExpire : current === 0
}

/** The policy the settings screen acts on for a group at `current` days: `neverExpireAllowed` applied. */
export function effectivePolicy(policy: ExpiryPolicy, current: number): ExpiryPolicy {
  return { ...policy, allowNeverExpire: neverExpireAllowed(policy, current) }
}
