// Signing who wrapped a member's entry (#280, docs/DESIGN.md, "Who wrapped a
// member's entry"). The record is evidence for the person deciding whether to
// accept a key change and authorizes nothing, so a failure to produce one must
// never block the wrap it describes: the entry then simply reads as "no signed
// record". The server takes both fields or neither.

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
