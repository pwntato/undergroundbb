import { describe, expect, it } from 'vitest'
import { SAFE_EXPIRY_POLICY } from './expiryPolicy'
import { settingsFormOf, startingDays } from './settingsFormValues'

const allow = { known: true, allowNeverExpire: true, defaultDays: 30 }
const forbid = { known: true, allowNeverExpire: false, defaultDays: 30 }
const base = { name: 'A', description: 'B', neverExpires: false, days: '14', currentDays: 14 }

describe('settingsFormOf', () => {
  it('carries the name and description through and parses the days', () => {
    expect(settingsFormOf({ ...base, policy: allow })).toEqual({
      name: 'A',
      description: 'B',
      expirationDays: 14,
    })
  })

  it('sends 0 only for a ticked box where never-expire is allowed', () => {
    expect(settingsFormOf({ ...base, neverExpires: true, policy: allow }).expirationDays).toBe(0)
    expect(settingsFormOf({ ...base, neverExpires: true, policy: forbid }).expirationDays).toBe(14)
  })

  it('turns an empty, zero or non-numeric days field into NaN so validation refuses it', () => {
    for (const days of ['', '0', '-3', 'abc']) {
      expect(settingsFormOf({ ...base, days, policy: allow }).expirationDays).toBeNaN()
      expect(settingsFormOf({ ...base, days, policy: forbid }).expirationDays).toBeNaN()
    }
  })

  it('does not let a stale ticked box turn an empty days field into never-expire where forbidden', () => {
    expect(
      settingsFormOf({ ...base, days: '', neverExpires: true, policy: forbid }).expirationDays,
    ).toBeNaN()
  })
})

describe('startingDays', () => {
  it("is the group's own days, or the deployment's default for a never-expire group", () => {
    expect(startingDays(45, { known: true, allowNeverExpire: true, defaultDays: 14 })).toBe('45')
    expect(startingDays(0, { known: true, allowNeverExpire: true, defaultDays: 14 })).toBe('14')
    expect(startingDays(0, { known: true, allowNeverExpire: false, defaultDays: 90 })).toBe('90')
  })
})

describe('saving a never-expire group before the policy is known (review of #357)', () => {
  it('keeps 0, so a rename made before /api/config answers does not switch the group to expiring', () => {
    const form = settingsFormOf({
      name: 'Renamed',
      description: '',
      neverExpires: true,
      days: startingDays(0, SAFE_EXPIRY_POLICY),
      policy: SAFE_EXPIRY_POLICY,
      currentDays: 0,
    })
    expect(form.expirationDays).toBe(0)
  })

  it('still sends days for a group that expires', () => {
    const form = settingsFormOf({
      name: 'A',
      description: '',
      neverExpires: false,
      days: '45',
      policy: SAFE_EXPIRY_POLICY,
      currentDays: 45,
    })
    expect(form.expirationDays).toBe(45)
  })
})

describe('a stale tick on a group that expires, before the policy is known', () => {
  it('does not become never-expire', () => {
    const form = settingsFormOf({
      name: 'A',
      description: '',
      neverExpires: true,
      days: '45',
      policy: SAFE_EXPIRY_POLICY,
      currentDays: 45,
    })
    expect(form.expirationDays).toBe(45)
  })
})
