// What a group's successor designations (#161) say right now, for the screen
// that manages them. Pure functions over the served rows, mirroring the
// rules lib/crypto/grant-chain's claim check and the server's claim endpoint
// apply, so the UI can say "this will work", "not yet" or "this has lapsed"
// before anyone signs anything.
//
// Advisory only. Nothing here verifies a signature, and it cannot see the one
// input the server alone has: the admins' last-login days. The server's claim
// check and every viewer's grant check are what decide; this just keeps an
// honest user from signing something they can already tell will be refused.

import type { DesignationRecord, GrantRecord } from '@/lib/crypto/grant-chain'

/** The designation period the admin may choose, in days; the UI suggests SUGGESTED. */
export const MIN_PERIOD_DAYS = 30
export const MAX_PERIOD_DAYS = 365
export const SUGGESTED_PERIOD_DAYS = 90

const DAY_MS = 24 * 60 * 60 * 1000
const KEY_DAY = /^(?:DESIGNATION|GRANT)#[0-9a-f-]{36}#(\d{4}-\d{2}-\d{2})#[0-9a-f]{16}$/

/** The UTC day (ms at midnight) a DESIGNATION# or GRANT# sort key is dated, or null if malformed. */
export function keyDayMs(sortKey: string): number | null {
  const m = KEY_DAY.exec(sortKey)
  if (m === null) return null
  const ms = Date.parse(`${m[1] ?? ''}T00:00:00Z`)
  return Number.isNaN(ms) ? null : ms
}

/** The UTC day (ms at midnight) containing nowMs. */
export function utcDayMs(nowMs: number): number {
  return Math.floor(nowMs / DAY_MS) * DAY_MS
}

/** YYYY-MM-DD for a UTC-midnight timestamp. */
export function formatDay(dayMs: number): string {
  return new Date(dayMs).toISOString().slice(0, 10)
}

export function addDays(dayMs: number, days: number): number {
  return dayMs + days * DAY_MS
}

interface MemberLike {
  readonly userId: string
  readonly role: string
}

/**
 * The admin's standing designation, after the rules that make an older or
 * disturbed one stop counting:
 *  - none: they have never designated anyone
 *  - revoked: their newest designation names nobody
 *  - cancelled: two designations on their newest day (order within a day is
 *    unknowable, so each cancels the other)
 *  - used: a successor already claimed it (each fires at most once)
 *  - lapsed: the admin received a grant dated on or after the designation's
 *    day (a demotion, removal or re-promotion), which voids it
 *  - successorGone: the named successor is no longer a member
 *  - active: it stands; claimableFrom is the first day the period has elapsed
 */
export type AdminSuccessorStatus =
  | { readonly kind: 'none' }
  | { readonly kind: 'revoked'; readonly day: number }
  | { readonly kind: 'cancelled'; readonly day: number }
  | { readonly kind: 'used'; readonly designation: DesignationRecord; readonly claimedBy: string }
  | { readonly kind: 'lapsed'; readonly designation: DesignationRecord; readonly since: number }
  | { readonly kind: 'successorGone'; readonly designation: DesignationRecord }
  | {
      readonly kind: 'active'
      readonly designation: DesignationRecord
      readonly successorUserId: string
      readonly periodDays: number
      readonly day: number
      readonly claimableFrom: number
    }

/** The newest designation of `adminUserId`, or the day two of them cancelled each other. */
function newestOf(
  adminUserId: string,
  designations: readonly DesignationRecord[],
):
  | { readonly d: DesignationRecord; readonly day: number }
  | { readonly cancelledDay: number }
  | null {
  let best: DesignationRecord[] = []
  let bestDay = -Infinity
  for (const d of designations) {
    if (d.adminUserId !== adminUserId) continue
    const day = keyDayMs(d.sortKey)
    if (day === null) continue
    if (day > bestDay) {
      bestDay = day
      best = [d]
    } else if (day === bestDay) {
      best.push(d)
    }
  }
  const first = best[0]
  if (first === undefined) return null
  if (best.length > 1) return { cancelledDay: bestDay }
  return { d: first, day: bestDay }
}

/** The earliest day on or after `fromDay` on which a grant TO `adminUserId` is dated, up to `toDay`. */
function firstGrantToAdmin(
  adminUserId: string,
  grants: readonly GrantRecord[],
  fromDay: number,
  toDay: number,
): number | null {
  let first: number | null = null
  for (const g of grants) {
    if (g.subjectUserId !== adminUserId) continue
    const day = keyDayMs(g.sortKey)
    if (day !== null && day >= fromDay && day <= toDay && (first === null || day < first)) {
      first = day
    }
  }
  return first
}

function claimedBy(sortKey: string, grants: readonly GrantRecord[]): string | null {
  const g = grants.find((x) => x.viaDesignation === sortKey)
  return g === undefined ? null : g.subjectUserId
}

export function adminSuccessorStatus(
  adminUserId: string,
  designations: readonly DesignationRecord[],
  grants: readonly GrantRecord[],
  members: readonly MemberLike[],
  nowMs: number,
): AdminSuccessorStatus {
  const newest = newestOf(adminUserId, designations)
  if (newest === null) return { kind: 'none' }
  if ('cancelledDay' in newest) return { kind: 'cancelled', day: newest.cancelledDay }
  const { d, day } = newest
  if (d.successorUserId === undefined || d.successorUserId === '') {
    return { kind: 'revoked', day }
  }
  const taker = claimedBy(d.sortKey, grants)
  if (taker !== null) return { kind: 'used', designation: d, claimedBy: taker }
  const since = firstGrantToAdmin(adminUserId, grants, day, utcDayMs(nowMs))
  if (since !== null) return { kind: 'lapsed', designation: d, since }
  if (!members.some((m) => m.userId === d.successorUserId)) {
    return { kind: 'successorGone', designation: d }
  }
  return {
    kind: 'active',
    designation: d,
    successorUserId: d.successorUserId,
    periodDays: d.periodDays,
    day,
    claimableFrom: addDays(day, d.periodDays),
  }
}

/** A designation that names the viewer and still stands, with whether the period has elapsed. */
export interface SuccessorOffer {
  readonly designation: DesignationRecord
  readonly adminUserId: string
  readonly periodDays: number
  readonly designationDay: number
  /** The first UTC day (ms) on which the period has elapsed. */
  readonly claimableFrom: number
  /** Whether claimDay is on or after claimableFrom. The server may still refuse (see not_inactive). */
  readonly periodElapsed: boolean
}

/**
 * The designations naming `userId` that still stand as of `claimDayMs` (the UTC
 * day a claim would be signed on): the admin's newest and not cancelled, still
 * an admin, not already used, and with no grant to the admin dated from the
 * designation's day through the claim day. Period elapsed or not, so a
 * successor can be told when they will be able to claim.
 */
export function successorOffers(
  userId: string,
  designations: readonly DesignationRecord[],
  grants: readonly GrantRecord[],
  members: readonly MemberLike[],
  claimDayMs: number,
): SuccessorOffer[] {
  const offers: SuccessorOffer[] = []
  const admins = new Set(
    designations.filter((d) => d.successorUserId === userId).map((d) => d.adminUserId),
  )
  for (const adminUserId of admins) {
    if (!members.some((m) => m.userId === adminUserId && m.role === 'admin')) continue
    const newest = newestOf(adminUserId, designations)
    if (newest === null || 'cancelledDay' in newest) continue
    const { d, day } = newest
    if (d.successorUserId !== userId) continue
    if (claimedBy(d.sortKey, grants) !== null) continue
    if (firstGrantToAdmin(adminUserId, grants, day, claimDayMs) !== null) continue
    const claimableFrom = addDays(day, d.periodDays)
    offers.push({
      designation: d,
      adminUserId,
      periodDays: d.periodDays,
      designationDay: day,
      claimableFrom,
      periodElapsed: claimDayMs >= claimableFrom,
    })
  }
  return offers
}
