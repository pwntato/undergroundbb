// What a client can show someone deciding whether to accept another user's key
// change (#62, docs/DESIGN.md "Other admins after an approval"): is there a
// signed rotation from the keys they saved to the keys the server serves now?
//
// The answer informs a human and authorizes nothing. Accepting always goes
// through the fingerprint comparison; this only says how much the server's
// own history backs the change.
//
//   - 'signed-rotation': the served KEYCHANGE# chain verifies (every link signed
//     by both keys it names, no gap, ending at the served key) and the rotation
//     right after the pinned epoch starts at the pinned key. Whoever held the
//     saved key made this change.
//   - 'no-link': the chain verifies but nothing in it starts at the saved key
//     for that epoch: the keys changed without a signature from the old ones.
//   - 'unverified': the chain does not verify, or does not end at the served key.
//
// Pure and never throws.

import { base64ToBytes } from './base64.js'
import { buildOwnKeyHistory, type WireKeyChange } from './own-history.js'
import type { PinRecord, ServedUserKeys } from './pin.js'

export type KeyChangeEvidence = 'signed-rotation' | 'no-link' | 'unverified'

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i])
}

export function keyChangeEvidence(input: {
  readonly userId: string
  readonly pin: Pick<PinRecord, 'signingPublicKeys' | 'keyEpoch'>
  readonly served: Pick<ServedUserKeys, 'signingPublicKey'>
  readonly changes: readonly WireKeyChange[]
}): KeyChangeEvidence {
  let servedCurrent: Uint8Array
  let pinned: Uint8Array[]
  try {
    servedCurrent = base64ToBytes(input.served.signingPublicKey)
    pinned = input.pin.signingPublicKeys.map((k) => base64ToBytes(k))
  } catch {
    return 'unverified'
  }
  // The chain is verified exactly as the caller's own is: the same links and
  // signatures, ending at the key we were told is current. No rosters: they are
  // the owner's to read and say nothing about this question.
  const history = buildOwnKeyHistory({
    userId: input.userId,
    ownSigningKey: servedCurrent,
    changes: input.changes,
    rosters: [],
  })
  if (history === null) return 'unverified'
  // The order of the pin's key list is not signed, so the link is matched
  // against the whole pinned set; chain continuity still decides.
  const next = history.links.find((l) => l.epoch === input.pin.keyEpoch + 1)
  return next !== undefined && pinned.some((k) => sameBytes(next.oldSigning, k))
    ? 'signed-rotation'
    : 'no-link'
}
