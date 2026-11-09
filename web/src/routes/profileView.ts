// What a profile page shows (#75), as plain data so the decisions are testable
// without rendering. Everything here comes from the users projection the
// server serves to any signed-in user, plus the fingerprint computed locally
// from the served keys (never taken from the server).

import { MAX_BIO_BYTES, MAX_BIO_CHARS, type UserProjection } from '@/lib/api/users'
import { servedFingerprint } from './runMemberVerification'

const MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
] as const

/**
 * "2026-11-08" as "8 November 2026"; null for anything that is not a real day.
 * A day past the end of its month (Feb 30, day 00) rolls over into another
 * month in `Date.UTC`, so comparing the month and year catches it.
 */
export function formatMemberSince(day: string | undefined): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day ?? '')
  if (m === null) return null
  const [, y, mo, d] = m
  const month = MONTHS[Number(mo) - 1]
  const date = new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d)))
  if (
    month === undefined ||
    date.getUTCFullYear() !== Number(y) ||
    date.getUTCMonth() !== Number(mo) - 1
  ) {
    return null
  }
  return `${String(Number(d))} ${month} ${y ?? ''}`
}

export interface ProfileView {
  readonly userId: string
  readonly deleted: boolean
  /** The username; empty for a deleted account. */
  readonly username: string
  /** "8 November 2026", or null when the account predates the field. */
  readonly memberSince: string | null
  readonly bio: string
  /** Computed from the served keys; null for a deleted or malformed account. */
  readonly fingerprint: string | null
}

export function profileView(user: UserProjection): ProfileView {
  const deleted = user.deleted === true
  return {
    userId: user.userId,
    deleted,
    username: deleted ? '' : user.username,
    memberSince: deleted ? null : formatMemberSince(user.createdDay),
    bio: deleted ? '' : (user.bio ?? ''),
    fingerprint: servedFingerprint(user),
  }
}

/** Characters in `text` as a person counts them (an emoji is one), the way the server caps a bio. */
export function bioLength(text: string): number {
  return Array.from(text.trim()).length
}

/** UTF-8 bytes in the trimmed `text`, which is what the server's byte cap counts. */
export function bioBytes(text: string): number {
  return new TextEncoder().encode(text.trim()).length
}

/**
 * Whether a bio draft can be saved: within both caps the server enforces, the
 * character cap and the byte cap. An empty draft is allowed, it clears the bio.
 */
export function bioFits(text: string): boolean {
  return bioLength(text) <= MAX_BIO_CHARS && bioBytes(text) <= MAX_BIO_BYTES
}
