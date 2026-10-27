// Signing who wrapped a member's entry (#280, docs/DESIGN.md, "Who wrapped a
// member's entry"). The record is evidence for the person deciding whether to
// accept a key change and authorizes nothing, so a failure to produce one must
// never block the wrap it describes: the entry then simply reads as "no signed
// record". The server takes both fields or neither.

import { ApiError } from '@/lib/api/auth'
import type { UserDetail } from '@/lib/api/users'
import type { SignWrapRecordRequest, SignWrapRecordResult } from '@/lib/crypto/worker-protocol'

export type SignWrapRecord = (
  req: Omit<SignWrapRecordRequest, 'kind' | 'id'>,
) => Promise<SignWrapRecordResult>

export interface WrapRecordFields {
  readonly wrapSignature?: string
  readonly wrapDay?: string
}

/**
 * The fields to send with a wrap, or none when there is no signer or signing
 * failed. `generation` and `keyEpoch` are the entry's own after the write.
 */
export async function wrapRecordFor(
  sign: SignWrapRecord | undefined,
  req: Omit<SignWrapRecordRequest, 'kind' | 'id'>,
): Promise<WrapRecordFields> {
  if (sign === undefined) return {}
  try {
    const { wrapSignature, wrapDay } = await sign(req)
    return { wrapSignature, wrapDay }
  } catch {
    return {}
  }
}

/**
 * The record for the caller's own entry at `generation`, signed to their own
 * current KeyEpoch (the value the server stamps as the entry's WrapEpoch), or
 * none when there is no signer or that epoch cannot be read. For the writes
 * that bring the caller's own entry to a new generation: a self re-key, a
 * self-wrap, a removal's start and a leave takeover.
 */
export async function ownWrapRecord(
  deps: {
    readonly selfUserId: string
    readonly getUserDetail?: (userId: string) => Promise<UserDetail>
    readonly signWrapRecord?: SignWrapRecord
  },
  groupId: string,
  generation: number,
): Promise<WrapRecordFields> {
  // No signer, no read: nothing here may add a request to a caller that signs nothing.
  if (deps.signWrapRecord === undefined || deps.getUserDetail === undefined) return {}
  let keyEpoch: number
  try {
    keyEpoch = (await deps.getUserDetail(deps.selfUserId)).keyEpoch
  } catch {
    return {}
  }
  return wrapRecordFor(deps.signWrapRecord, {
    userId: deps.selfUserId,
    groupId,
    memberUserId: deps.selfUserId,
    generation,
    keyEpoch,
    reason: 'self',
  })
}

/**
 * Sends a wrap with its record, and once more without it if the server refuses
 * the record as `bad_signature`. The epoch signed comes from a read that can lag
 * a just-committed rotation, and the record is evidence only: a refused one must
 * not turn a wrap that used to succeed into a failure. A refusal writes nothing,
 * so the second send cannot duplicate; if the start's own signature was the real
 * cause it fails the same way and that error is the one thrown.
 */
export async function sendWithRecord(
  fields: WrapRecordFields,
  send: (fields: WrapRecordFields) => Promise<void>,
): Promise<void> {
  try {
    await send(fields)
  } catch (err) {
    if (
      fields.wrapSignature !== undefined &&
      err instanceof ApiError &&
      err.code === 'bad_signature'
    ) {
      await send({})
      return
    }
    throw err
  }
}
