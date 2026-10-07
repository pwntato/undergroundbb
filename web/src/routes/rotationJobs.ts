// Who may run a key-rotation job, and the removal-then-rotate sequence, kept
// out of GroupMembersScreen so the rules that were wrong in review of #179
// (two jobs at once; a stalled rotation after an ambiguous removal) are
// unit-tested instead of living in untested component glue.
//
// Why one job at a time matters beyond wasted work: if a removal moves the
// rotation marker to N+1 while another job is mid-batch at N, that job's next
// batch is refused (rotation_not_active) and runRotation restarts from a fresh
// read -- with the OTHER job's `exclude` set. A catch-up job has none, so it
// would resume the new rotation without excluding the removed user itself.
// (The marker's signed record names them too, so the exclusion no longer
// depends on which job started the rotation; see runRotation.ts, #178.)

import type { MemberRole } from '@/lib/api/groups'
import {
  runRemoveMember,
  type RemoveDeps,
  type RemoveResult,
  type RotationNeed,
  rotationNeededAfter,
} from './runRemoveMember'
import { runRotation, type RotationDeps, type RotationOutcome } from './runRotation'

/** Single-flight lock. Release only works for the holder, and only once. */
export interface RotationGuard {
  /** A release function if the lock was free, null if a job already holds it. */
  tryAcquire(): (() => void) | null
  readonly held: boolean
  /** Calls `listener` with the new value whenever `held` changes; returns an unsubscribe. */
  subscribe(listener: (held: boolean) => void): () => void
}

export function createRotationGuard(): RotationGuard {
  let holder: object | null = null
  const listeners = new Set<(held: boolean) => void>()
  const notify = (held: boolean) => {
    for (const l of [...listeners]) {
      l(held)
    }
  }
  return {
    tryAcquire() {
      if (holder !== null) {
        return null
      }
      const token = {}
      holder = token
      notify(true)
      return () => {
        // A stale or repeated release must not free someone else's hold.
        if (holder === token) {
          holder = null
          notify(false)
        }
      }
    },
    get held() {
      return holder !== null
    },
    subscribe(listener) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
  }
}

// A job outlives the screen that started it (Back stays enabled), so the guard
// cannot belong to the component: reopening the same group mounts a new screen
// that must see the old job still running. One guard per group for the life of
// the tab; they are a few bytes each, so they are never dropped.
const guards = new Map<string, RotationGuard>()

/** The tab-wide guard for groupId's rotation jobs. */
export function rotationGuardFor(groupId: string): RotationGuard {
  let guard = guards.get(groupId)
  if (guard === undefined) {
    guard = createRotationGuard()
    guards.set(groupId, guard)
  }
  return guard
}

/**
 * The on-load catch-up an admin runs when opening a Rotating group. Skipped
 * (busy) while another job holds the guard: that job is already doing this.
 */
export async function catchUpRotation(
  guard: RotationGuard,
  deps: RotationDeps,
  groupId: string,
): Promise<{ readonly busy: true } | { readonly busy: false; readonly outcome: RotationOutcome }> {
  const release = guard.tryAcquire()
  if (release === null) {
    return { busy: true }
  }
  try {
    return { busy: false, outcome: await runRotation(deps, groupId) }
  } finally {
    release()
  }
}

export interface RemoveAndRotateDeps {
  readonly guard: RotationGuard
  readonly remove: RemoveDeps
  readonly rotation: RotationDeps
}

export type RemoveAndRotateResult =
  /** Another rotation job is running; nothing was read, minted or sent. */
  | { readonly busy: true }
  | {
      readonly busy: false
      readonly removal: RemoveResult
      /** Present when a rotation was run (or resumed) after the removal attempt. */
      readonly rotation?: RotationOutcome
      readonly need: RotationNeed
    }

/**
 * Removes a member and then drives the rotation it started, holding the guard
 * for the whole sequence (the removal request itself moves the marker, so the
 * hold has to begin before it). `rotatingGroup` is the roster's view of the
 * group's mode, used only to decide whether an inconclusive outcome needs a
 * rotation run; the removal itself reads the mode fresh.
 */
export async function removeAndRotate(
  deps: RemoveAndRotateDeps,
  groupId: string,
  subjectUserId: string,
  subjectRole: MemberRole,
  rotatingGroup: boolean,
): Promise<RemoveAndRotateResult> {
  const release = deps.guard.tryAcquire()
  if (release === null) {
    return { busy: true }
  }
  try {
    const removal = await runRemoveMember(deps.remove, groupId, subjectUserId, subjectRole)
    const need = rotationNeededAfter(removal, rotatingGroup, subjectUserId)
    if (need.run) {
      const rotation = await runRotation(deps.rotation, groupId, { exclude: need.exclude })
      return { busy: false, removal, rotation, need }
    }
    return { busy: false, removal, need }
  } finally {
    release()
  }
}
