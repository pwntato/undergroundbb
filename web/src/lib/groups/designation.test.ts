import { describe, expect, it } from 'vitest'
import type { DesignationRecord, GrantRecord } from '@/lib/crypto/grant-chain'
import { adminSuccessorStatus, formatDay, keyDayMs, successorOffers, utcDayMs } from './designation'

const ADMIN = 'aaaaaaaa-1111-4111-8111-111111111111'
const BOB = 'bbbbbbbb-2222-4222-8222-222222222222'
const CAT = 'cccccccc-3333-4333-8333-333333333333'
const RAND = '0123456789abcdef'

const day = (iso: string) => Date.parse(`${iso}T00:00:00Z`)
const dKey = (admin: string, iso: string, rand = RAND) => `DESIGNATION#${admin}#${iso}#${rand}`
const gKey = (subject: string, iso: string, rand = RAND) => `GRANT#${subject}#${iso}#${rand}`

function designation(
  iso: string,
  successor: string | undefined,
  overrides: Partial<DesignationRecord> = {},
): DesignationRecord {
  return {
    sortKey: dKey(ADMIN, iso),
    adminUserId: ADMIN,
    ...(successor !== undefined && { successorUserId: successor }),
    periodDays: 90,
    adminGrantRef: gKey(ADMIN, '2026-01-01'),
    signature: 'sig',
    ...overrides,
  }
}

function grant(subject: string, iso: string, overrides: Partial<GrantRecord> = {}): GrantRecord {
  return {
    sortKey: gKey(subject, iso),
    subjectUserId: subject,
    grantedRole: 'member',
    grantorUserId: ADMIN,
    signature: 'sig',
    ...overrides,
  }
}

const MEMBERS = [
  { userId: ADMIN, role: 'admin' },
  { userId: BOB, role: 'member' },
  { userId: CAT, role: 'member' },
]
const NOW = day('2026-09-01')

describe('days', () => {
  it('reads the day of a DESIGNATION# or GRANT# key, and rejects anything else', () => {
    expect(keyDayMs(dKey(ADMIN, '2026-03-04'))).toBe(day('2026-03-04'))
    expect(keyDayMs(gKey(BOB, '2026-03-04'))).toBe(day('2026-03-04'))
    expect(keyDayMs('nonsense')).toBeNull()
    expect(keyDayMs(dKey(ADMIN, '2026-13-45'))).toBeNull()
  })

  it('floors a clock to its UTC day', () => {
    expect(utcDayMs(Date.parse('2026-09-01T23:59:59Z'))).toBe(day('2026-09-01'))
    expect(formatDay(day('2026-09-01'))).toBe('2026-09-01')
  })
})

describe('adminSuccessorStatus', () => {
  const status = (ds: DesignationRecord[], gs: GrantRecord[] = [], ms = MEMBERS) =>
    adminSuccessorStatus(ADMIN, ds, gs, ms, NOW)

  it('says none when the admin never designated', () => {
    expect(status([]).kind).toBe('none')
    // Someone else's designation is not theirs.
    const other = designation('2026-06-01', CAT, {
      adminUserId: BOB,
      sortKey: dKey(BOB, '2026-06-01'),
    })
    expect(status([other]).kind).toBe('none')
  })

  it('is active with the day the period elapses', () => {
    const s = status([designation('2026-06-01', BOB)])
    expect(s).toMatchObject({ kind: 'active', successorUserId: BOB, periodDays: 90 })
    if (s.kind === 'active') expect(formatDay(s.claimableFrom)).toBe('2026-08-30')
  })

  it('judges the newest designation: a later revocation ends it, a later one replaces it', () => {
    const first = designation('2026-05-01', BOB)
    expect(status([first, designation('2026-06-01', undefined)]).kind).toBe('revoked')
    const s = status([designation('2026-06-01', CAT), first])
    expect(s).toMatchObject({ kind: 'active', successorUserId: CAT })
  })

  it('treats two designations on the newest day as cancelling each other', () => {
    const a = designation('2026-06-01', BOB)
    const b = designation('2026-06-01', CAT, {
      sortKey: dKey(ADMIN, '2026-06-01', 'fedcba9876543210'),
    })
    expect(status([a, b]).kind).toBe('cancelled')
    // An older pair no longer matters once a newer single one exists.
    expect(status([a, b, designation('2026-07-01', BOB)]).kind).toBe('active')
  })

  it('lapses when the admin received a grant on or after the designation day', () => {
    const d = designation('2026-06-01', BOB)
    expect(status([d], [grant(ADMIN, '2026-06-01')])).toMatchObject({
      kind: 'lapsed',
      since: day('2026-06-01'),
    })
    expect(status([d], [grant(ADMIN, '2026-07-10')])).toMatchObject({
      kind: 'lapsed',
      since: day('2026-07-10'),
    })
    // Before the designation day is the grant it was signed against: no lapse.
    expect(status([d], [grant(ADMIN, '2026-05-31')]).kind).toBe('active')
    // A grant to someone else is not the admin's own role changing.
    expect(status([d], [grant(CAT, '2026-07-10')]).kind).toBe('active')
  })

  it('is used once a grant cites it, and says who claimed', () => {
    const d = designation('2026-06-01', BOB)
    const claim = grant(BOB, '2026-08-31', { grantedRole: 'admin', viaDesignation: d.sortKey })
    expect(status([d], [claim])).toMatchObject({ kind: 'used', claimedBy: BOB })
  })

  it('notices a successor who is no longer a member', () => {
    const d = designation('2026-06-01', BOB)
    expect(status([d], [], [MEMBERS[0] as (typeof MEMBERS)[number]]).kind).toBe('successorGone')
  })
})

describe('successorOffers', () => {
  const offers = (
    ds: DesignationRecord[],
    gs: GrantRecord[] = [],
    at = '2026-09-01',
    ms = MEMBERS,
    who = BOB,
  ) => successorOffers(who, ds, gs, ms, day(at))

  it('offers a designation naming the viewer, flagging whether the period has elapsed', () => {
    const d = designation('2026-06-01', BOB)
    const early = offers([d], [], '2026-08-29')
    expect(early).toHaveLength(1)
    expect(early[0]).toMatchObject({ adminUserId: ADMIN, periodDays: 90, periodElapsed: false })
    expect(formatDay(early[0]?.claimableFrom ?? 0)).toBe('2026-08-30')
    // The day it elapses, and after: the floor is claimDay - designationDay >= period.
    expect(offers([d], [], '2026-08-30')[0]?.periodElapsed).toBe(true)
    expect(offers([d], [], '2026-09-30')[0]?.periodElapsed).toBe(true)
  })

  it('offers nothing to someone the designation does not name', () => {
    expect(offers([designation('2026-06-01', BOB)], [], '2026-09-01', MEMBERS, CAT)).toEqual([])
  })

  it('drops a designation the admin superseded, revoked or cancelled', () => {
    const d = designation('2026-06-01', BOB)
    expect(offers([d, designation('2026-07-01', CAT)])).toEqual([])
    expect(offers([d, designation('2026-07-01', undefined)])).toEqual([])
    const same = designation('2026-06-01', CAT, {
      sortKey: dKey(ADMIN, '2026-06-01', 'fedcba9876543210'),
    })
    expect(offers([d, same])).toEqual([])
  })

  it('drops it once the admin lost admin or received a grant on or after the designation day', () => {
    const d = designation('2026-06-01', BOB)
    expect(
      offers([d], [], '2026-09-01', [{ userId: ADMIN, role: 'member' }, ...MEMBERS.slice(1)]),
    ).toEqual([])
    expect(offers([d], [grant(ADMIN, '2026-06-01')])).toEqual([])
    expect(offers([d], [grant(ADMIN, '2026-09-01')])).toEqual([])
    // A grant after the claim day being checked is not yet part of the window.
    expect(offers([d], [grant(ADMIN, '2026-09-02')])).toHaveLength(1)
    // The admin's pre-designation grant is fine.
    expect(offers([d], [grant(ADMIN, '2026-05-31')])).toHaveLength(1)
  })

  it('drops it once a claim cites it', () => {
    const d = designation('2026-06-01', BOB)
    const claim = grant(BOB, '2026-08-31', { grantedRole: 'admin', viaDesignation: d.sortKey })
    expect(offers([d], [claim])).toEqual([])
  })
})
