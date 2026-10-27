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
//   - The job that follows the start checks the caller's own pins, records and
//     removal links under the signing key they rotated away from, through their
//     verified key history (lib/crypto/own-history). When that history cannot
//     be built the job stops and reports, and resumes once it can.
//   - An Open group has no re-key, so any member, not only an admin, brings
//     their own entry to the new key with a self-wrap from the same row: it mints
//     nothing, and the server's transaction consumes the row.

import { ApiError } from '@/lib/api/auth'
import type { SelfWrapRequest, TakeOverRotationRequest } from '@/lib/api/groups'
import type { HandoffEntry } from '@/lib/api/keyRotation'
import type {
  SelfWrapFromHandoffRequest,
  StartGroupRotationResult,
  StartSelfRekeyRequest,
} from '@/lib/crypto/worker-protocol'
import { runRotation, type RotationDeps, type RotationOutcome } from './runRotation'
import { ownWrapRecord, sendWithRecord } from './wrapRecord'

export interface SelfRekeyDeps extends RotationDeps {
  readonly startSelfRekeyCrypto: (
    req: Omit<StartSelfRekeyRequest, 'kind' | 'id'>,
  ) => Promise<StartGroupRotationResult>
  readonly selfRekey: (groupId: string, req: TakeOverRotationRequest) => Promise<void>
  readonly selfWrapCrypto: (
    req: Omit<SelfWrapFromHandoffRequest, 'kind' | 'id'>,
  ) => Promise<SelfWrapRequest['wrappedKey']>
  readonly selfWrap: (groupId: string, req: SelfWrapRequest) => Promise<void>
  readonly deleteHandoff: (groupId: string) => Promise<void>
}

export type SelfRekeyOutcome =
  /** The start ran (or a rotation was already running) and the job carried on. */
  | { readonly status: 'rekeyed'; readonly rotation: RotationOutcome }
  /** The row could never be used and was deleted. */
  | { readonly status: 'stale' }
  /** The caller is not an admin of the group (any more); the row is left to the server's sweep. */
  | { readonly status: 'not-admin' }
  /** An Open group: the caller's entry now holds the same key under their new one. */
  | { readonly status: 'wrapped' }
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
  // A public group answers a non-member with 200 and an empty role; the server
  // would refuse the self-wrap with a 404, which is not a retryable stop.
  if (detail.role === '') return { status: 'not-admin' }
  if (detail.revocationMode === 'open' || detail.visibility !== 'private') {
    return selfWrapOpen(deps, row, detail.generation, staleRow)
  }
  if (detail.role !== 'admin') return { status: 'not-admin' }
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
    await sendWithRecord(await ownWrapRecord(deps, groupId, minted.generation), (record) =>
      deps.selfRekey(groupId, {
        generation: minted.generation,
        link: minted.link,
        wrappedKey: minted.removerWrappedKey,
        startSignature: minted.startSignature,
        ...record,
      }),
    )
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

/**
 * The Open-group branch: any member self-wraps. The caller's own entry already
 * past the row's generation means nothing can use the row (the same rule as the
 * re-key); a server `handoff_stale` is the same answer, and only these delete it.
 */
async function selfWrapOpen(
  deps: SelfRekeyDeps,
  row: HandoffEntry,
  entryGeneration: number,
  staleRow: () => Promise<SelfRekeyOutcome>,
): Promise<SelfRekeyOutcome> {
  const { groupId } = row
  if (entryGeneration !== row.generation) return staleRow()
  let wrappedKey
  try {
    wrappedKey = await deps.selfWrapCrypto({
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
    await sendWithRecord(await ownWrapRecord(deps, groupId, row.generation), (record) =>
      deps.selfWrap(groupId, { generation: row.generation, wrappedKey, ...record }),
    )
  } catch (err) {
    if (codeOf(err) === 'handoff_stale') return staleRow()
    return { status: 'incomplete', reason: describe(err) }
  }
  return { status: 'wrapped' }
}
