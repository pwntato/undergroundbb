// Checking the signed record of who wrapped a member's group-key entry (#280,
// docs/DESIGN.md "Who wrapped a member's entry"). Evidence for the person
// deciding whether to accept a key change; it authorizes nothing.
//
// The payload is rebuilt from the entry's OWN served generation and wrapEpoch,
// never from anything the record carries, so a record signed for another
// generation or epoch does not verify. The signature is checked under the
// wrapper's signing keys for the signed day: their current key from the day it
// was introduced, and each superseded key up to the rotation that ended it
// (both keys are candidates on a rotation day, day resolution).
//
//   - 'approved': a signed record, reason 'approval', wrapper is not the member.
//   - 'self': a signed record, reason 'self', wrapper is the member.
//   - 'none': the entry carries no record.
//   - 'invalid': a record is there and does not verify, or its reason does not
//     fit who signed it. Not the same as 'none': something was written.
//   - 'unchecked': the facts to check it were missing or unreadable (no
//     wrapEpoch served, the wrapper's key chain does not verify). Never 'none'.
//
// The wrapper's keys are taken as given: the caller anchors them to a key it
// already trusts first (routes/runAcceptKeyChange). With no roster behind the
// wrapper's key rotations, a leaked superseded key of theirs can sign a record
// dated anywhere in that key's interval and it verifies; that is accepted, as
// the record is evidence only (docs/DESIGN.md "Who wrapped a member's entry").
//
// Pure and never throws.

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import { wrapRecordPayload } from './group.js'
import { buildOwnKeyHistory, signingKeysOn, type WireKeyChange } from './own-history.js'

export interface WireWrapRecord {
  readonly wrapperUserId: string
  readonly reason: string
  readonly day: string
  readonly signature: string
}

export type WrapEvidence =
  | { readonly kind: 'approved'; readonly wrapperUserId: string }
  | { readonly kind: 'self' }
  | { readonly kind: 'none' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'unchecked'; readonly reason: string }

/** The wrapper's served current signing key and key-change chain. */
export interface WrapperKeys {
  readonly signingPublicKey: string
  readonly keyChanges: readonly WireKeyChange[]
}

const DAY = /^\d{4}-\d{2}-\d{2}$/

export function checkWrapRecord(input: {
  readonly groupId: string
  readonly memberUserId: string
  readonly generation: number
  readonly wrapEpoch: number | undefined
  readonly record: WireWrapRecord | undefined
  /** Read only when there is a record to check; absent until then. */
  readonly wrapper: WrapperKeys | undefined
}): WrapEvidence {
  const { record } = input
  if (record === undefined) return { kind: 'none' }
  if (input.wrapEpoch === undefined) {
    return {
      kind: 'unchecked',
      reason: 'the server did not say which keys the entry was wrapped to',
    }
  }
  const isSelf = record.reason === 'self'
  if (!isSelf && record.reason !== 'approval') return { kind: 'invalid' }
  if (isSelf !== (record.wrapperUserId === input.memberUserId)) return { kind: 'invalid' }
  if (!DAY.test(record.day)) return { kind: 'invalid' }
  if (input.wrapper === undefined) {
    return { kind: 'unchecked', reason: 'their key history was not read' }
  }
  let signature: Uint8Array
  let current: Uint8Array
  try {
    signature = base64ToBytes(record.signature)
    current = base64ToBytes(input.wrapper.signingPublicKey)
  } catch {
    return { kind: 'unchecked', reason: 'the keys served for the wrapper are malformed' }
  }
  const history = buildOwnKeyHistory({
    userId: record.wrapperUserId,
    ownSigningKey: current,
    changes: input.wrapper.keyChanges,
    rosters: [],
  })
  if (history === null) {
    return { kind: 'unchecked', reason: "the wrapper's key history does not verify" }
  }
  const payload = wrapRecordPayload(
    input.groupId,
    record.wrapperUserId,
    input.memberUserId,
    input.generation,
    input.wrapEpoch,
    record.reason as 'self' | 'approval',
    record.day,
  )
  return signingKeysOn(history, current, record.day).some((k) =>
    verify(k, SigningContext.WrapRecord, payload, signature),
  )
    ? isSelf
      ? { kind: 'self' }
      : { kind: 'approved', wrapperUserId: record.wrapperUserId }
    : { kind: 'invalid' }
}
