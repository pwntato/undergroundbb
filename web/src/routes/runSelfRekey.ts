// The self re-key (#62, docs/DESIGN.md, "The self re-key must survive a closed
// tab"): after an admin rotated their account keys, each Rotating group they
// administer holds a HANDOFF# row, the group's key wrapped to their NEW key.
// This runs the start from that row and then the ordinary rotation job, which
// re-wraps everyone else. Plain function over injected deps, like runRotation.
//
//   - The row, not the caller's MEMBER# entry, is where the old key comes from:
//     the entry is wrapped to the key they rotated away from.
//   - A row is deleted only when the SERVER says it can never be used (409
//     handoff_stale), or the caller's own entry has already moved past it. Never
//     because it is missing from a list: the group list is an eventually
//     consistent index, and a row can be the only copy of a key.
//   - An unreadable row (unwrap fails) is reported and kept: it may be a swapped
//     row, but deleting on a decrypt error would also delete the last copy.
//   - Open groups wait for the self-wrap, which has no endpoint yet; they are
//     reported and left alone.

import { ApiError } from '@/lib/api/auth'
import type { TakeOverRotationRequest } from '@/lib/api/groups'
import type { HandoffEntry } from '@/lib/api/keyRotation'
import type { StartGroupRotationResult, StartSelfRekeyRequest } from '@/lib/crypto/worker-protocol'
import { runRotation, type RotationDeps, type RotationOutcome } from './runRotation'

export interface SelfRekeyDeps extends RotationDeps {
  readonly startSelfRekeyCrypto: (
    req: Omit<StartSelfRekeyRequest, 'kind' | 'id'>,
  ) => Promise<StartGroupRotationResult>
  readonly selfRekey: (groupId: string, req: TakeOverRotationRequest) => Promise<void>
  readonly deleteHandoff: (groupId: string) => Promise<void>
}

export type SelfRekeyOutcome =
  /** The start ran (or a rotation was already running) and the job carried on. */
  | { readonly status: 'rekeyed'; readonly rotation: RotationOutcome }
  /** The row could never be used and was deleted. */
  | { readonly status: 'stale' }
  /** The caller is not an admin of the group (any more); the row is left to the server's sweep. */
  | { readonly status: 'not-admin' }
  /** An Open group: its self-wrap is not built yet; the row is kept. */
  | { readonly status: 'open' }
  | { readonly status: 'incomplete'; readonly reason: string }

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function codeOf(err: unknown): string | undefined {
  return err instanceof ApiError ? err.code : undefined
}

export async function runSelfRekey(
  deps: SelfRekeyDeps,
  row: HandoffEntry,
): Promise<SelfRekeyOutcome> {
  const { groupId } = row
  const continueJob = async (): Promise<SelfRekeyOutcome> => ({
    status: 'rekeyed',
    rotation: await runRotation(deps, groupId),
  })
  const staleRow = async (): Promise<SelfRekeyOutcome> => {
    try {
      await deps.deleteHandoff(groupId)
    } catch (err) {
      return { status: 'incomplete', reason: `could not clear a used-up handoff: ${describe(err)}` }
    }
    return { status: 'stale' }
  }

  let detail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { status: 'not-admin' }
    return { status: 'incomplete', reason: describe(err) }
  }
  if (detail.role !== 'admin') return { status: 'not-admin' }
  if (detail.revocationMode === 'open' || detail.visibility !== 'private') {
    return { status: 'open' }
  }
  // A rotation is already running (this start's own, interrupted, or another
  // admin's): the start is not ours to make; the job resumes or reports.
  if (detail.rotation !== undefined) return continueJob()
  // The caller's own entry already moved past the row: nothing can use it.
  if (detail.generation !== row.generation) return staleRow()

  let minted: StartGroupRotationResult
  try {
    minted = await deps.startSelfRekeyCrypto({
      userId: deps.selfUserId,
      groupId,
      handoffGeneration: row.generation,
      handoffWrappedKey: row.wrappedGroupKey,
    })
  } catch (err) {
    return {
      status: 'incomplete',
      reason: `could not open the saved key for this group: ${describe(err)}`,
    }
  }
  try {
    await deps.selfRekey(groupId, {
      generation: minted.generation,
      link: minted.link,
      wrappedKey: minted.removerWrappedKey,
      startSignature: minted.startSignature,
    })
  } catch (err) {
    switch (codeOf(err)) {
      case 'handoff_stale':
        return staleRow()
      case 'rotation_in_progress':
        return continueJob()
      default:
        return { status: 'incomplete', reason: describe(err) }
    }
  }
  return continueJob()
}
