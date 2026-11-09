import { describe, expect, it } from 'vitest'
import {
  chosenExpirationDays,
  effectivePolicy,
  expiryPolicyOf,
  neverExpireAllowed,
  SAFE_EXPIRY_POLICY,
} from './expiryPolicy'

describe('expiryPolicyOf', () => {
  it('reads both settings from the config', () => {
    expect(expiryPolicyOf({ allowGroupExpirationOff: true, defaultExpirationDays: 7 })).toEqual({
      known: true,
      allowNeverExpire: true,
      defaultDays: 7,
    })
    expect(expiryPolicyOf({ allowGroupExpirationOff: false, defaultExpirationDays: 90 })).toEqual({
      known: true,
      allowNeverExpire: false,
      defaultDays: 90,
    })
  })

  it('treats anything but boolean true as not allowed', () => {
    for (const v of ['true', 1, null, undefined, {}]) {
      expect(
        expiryPolicyOf({ allowGroupExpirationOff: v, defaultExpirationDays: 7 }).allowNeverExpire,
      ).toBe(false)
    }
  })

  it('falls back to 30 days for a default that is not a whole number from 1 to 3650', () => {
    for (const d of [0, -1, 1.5, 3651, Number.NaN, '30', null, undefined]) {
      expect(
        expiryPolicyOf({ allowGroupExpirationOff: true, defaultExpirationDays: d }).defaultDays,
      ).toBe(30)
    }
    expect(
      expiryPolicyOf({ allowGroupExpirationOff: true, defaultExpirationDays: 1 }).defaultDays,
    ).toBe(1)
    expect(
      expiryPolicyOf({ allowGroupExpirationOff: true, defaultExpirationDays: 3650 }).defaultDays,
    ).toBe(3650)
  })

  it('is the safe policy for a body that is not an object', () => {
    for (const body of [null, undefined, 'x', 3]) {
      expect(expiryPolicyOf(body)).toEqual(SAFE_EXPIRY_POLICY)
    }
    expect(SAFE_EXPIRY_POLICY).toEqual({ known: false, allowNeverExpire: false, defaultDays: 30 })
  })
})

describe('chosenExpirationDays', () => {
  const allow = { known: true, allowNeverExpire: true, defaultDays: 30 }
  const forbid = { known: true, allowNeverExpire: false, defaultDays: 30 }

  it('is 0 only when ticked and allowed', () => {
    expect(chosenExpirationDays({ neverExpires: true, policy: allow, days: 12 })).toBe(0)
    expect(chosenExpirationDays({ neverExpires: true, policy: forbid, days: 12 })).toBe(12)
    expect(chosenExpirationDays({ neverExpires: false, policy: allow, days: 12 })).toBe(12)
    expect(chosenExpirationDays({ neverExpires: false, policy: forbid, days: 12 })).toBe(12)
  })

  it('passes an invalid days value through so validation can refuse it', () => {
    expect(chosenExpirationDays({ neverExpires: true, policy: forbid, days: Number.NaN })).toBeNaN()
  })
})

describe('neverExpireAllowed', () => {
  const known = (allow: boolean) => ({ known: true, allowNeverExpire: allow, defaultDays: 30 })

  it("is the deployment's answer once it is known, whatever the group has now", () => {
    for (const current of [0, 30]) {
      expect(neverExpireAllowed(known(true), current)).toBe(true)
      expect(neverExpireAllowed(known(false), current)).toBe(false)
    }
  })

  it('lets a never-expire group keep it, and offers nothing to another, while it is unknown', () => {
    expect(neverExpireAllowed(SAFE_EXPIRY_POLICY, 0)).toBe(true)
    expect(neverExpireAllowed(SAFE_EXPIRY_POLICY, 30)).toBe(false)
  })

  it('effectivePolicy changes only allowNeverExpire', () => {
    expect(effectivePolicy({ known: false, allowNeverExpire: false, defaultDays: 14 }, 0)).toEqual({
      known: false,
      allowNeverExpire: true,
      defaultDays: 14,
    })
    expect(effectivePolicy(known(false), 0)).toEqual(known(false))
  })
})
