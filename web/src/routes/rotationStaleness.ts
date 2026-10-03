// The staleness deadline for a key rotation -- issue #58, slice 4b.
// docs/DESIGN.md, "Revocation mode": rotation is client-driven and the group
// key exists in plaintext only in a member's browser, so nothing server-side
// can finish one. A rotation whose client never came back leaves the removed
// member reading every new post, so an admin who loads the group compares the
// marker's timestamp to this deadline and, past it, is told. Detection lives
// where the remedy lives.

import type { MembersView } from './runGroupMembers'

/**
 * How long a rotation may run before an admin is told it has stalled. A
 * rotation is a few batches of 25 re-wraps, so minutes in practice; an hour
 * leaves room for a slow network or a laptop that slept without raising an
 * alarm over a rotation that is merely still being worked on.
 */
export const ROTATION_STALE_AFTER_MS = 60 * 60 * 1000

export type RotationNotice =
  /** This admin holds the new key, so loading the group resumes the rotation. */
  | { readonly kind: 'resumable'; readonly startedBy: string; readonly ageMs: number | null }
  /** Only an admin who already holds the new key can finish it. */
  | {
      readonly kind: 'needs-other-admin'
      readonly startedBy: string
      readonly ageMs: number | null
    }

/**
 * The warning an admin should see for this view, or null. Only admins are
 * told (they are the only ones who can act), and only past the deadline. An
 * unparseable timestamp counts as stale: a banner shown wrongly costs a
 * glance, a rotation hidden by bad data costs the removal.
 */
export function rotationNotice(view: MembersView, nowMs: number): RotationNotice | null {
  const marker = view.rotation
  if (marker === undefined || view.myRole !== 'admin') {
    return null
  }
  const started = Date.parse(marker.startedAt)
  const ageMs = Number.isNaN(started) ? null : nowMs - started
  if (ageMs !== null && ageMs < ROTATION_STALE_AFTER_MS) {
    return null
  }
  const kind = view.myGeneration === marker.generation ? 'resumable' : 'needs-other-admin'
  return { kind, startedBy: marker.startedBy, ageMs }
}

/** "about 3 hours", for the banner. Null age (bad timestamp) reads as "a while". */
export function describeAge(ageMs: number | null): string {
  if (ageMs === null) {
    return 'a while'
  }
  const minutes = Math.floor(ageMs / 60_000)
  if (minutes < 60) {
    return `${String(minutes)} ${minutes === 1 ? 'minute' : 'minutes'}`
  }
  const hours = Math.floor(minutes / 60)
  if (hours < 48) {
    return `about ${String(hours)} ${hours === 1 ? 'hour' : 'hours'}`
  }
  return `about ${String(Math.floor(hours / 24))} days`
}
