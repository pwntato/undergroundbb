// Fixtures for tests that need a caller whose keys really rotated: a KEYCHANGE#
// link signed by both keys over the same payload the app builds, and the
// roster behind its digest. Test-only; nothing in the app imports this.

import { bytesToBase64 } from './base64.js'
import { SigningContext, sign, type SigningKey } from './ed25519.js'
import { keyRotationPayload, rosterDigest, rosterEntryId } from './key-rotation.js'
import type { WireKeyChange, WireKeyChangeRoster } from './own-history.js'

const b64 = bytesToBase64
const WRAP_OLD = new Uint8Array(32).fill(3)
const WRAP_NEW = new Uint8Array(32).fill(4)

/** The roster id of a row: what rotation lists for it and what ownSignerAccepted looks for. */
export function rowId(sk: string, signature: Uint8Array): Uint8Array {
  return rosterEntryId(sk, signature)
}

/**
 * One rotation: `epoch` is the KeyEpoch it produces (1 for the first).
 * `listed` are the roster ids the rotation signs over; `served` can differ
 * from `listed` to model a server that serves a different list.
 */
export function makeKeyChange(opts: {
  userId: string
  from: SigningKey
  to: SigningKey
  epoch: number
  day: string
  listed?: readonly Uint8Array[]
  served?: readonly Uint8Array[]
}): { change: WireKeyChange; roster: WireKeyChangeRoster } {
  const listed = opts.listed ?? []
  const digest = rosterDigest(listed)
  const payload = keyRotationPayload(
    opts.userId,
    opts.from.publicKey,
    WRAP_OLD,
    opts.to.publicKey,
    WRAP_NEW,
    opts.day,
    opts.epoch - 1,
    digest,
  )
  return {
    change: {
      keyEpoch: opts.epoch,
      day: opts.day,
      oldSigningPublicKey: b64(opts.from.publicKey),
      oldWrappingPublicKey: b64(WRAP_OLD),
      newSigningPublicKey: b64(opts.to.publicKey),
      newWrappingPublicKey: b64(WRAP_NEW),
      rosterDigest: b64(digest),
      oldSignature: b64(sign(opts.from, SigningContext.KeyRotation, payload)),
      newSignature: b64(sign(opts.to, SigningContext.KeyRotation, payload)),
    },
    roster: { keyEpoch: opts.epoch, roster: (opts.served ?? listed).map(b64) },
  }
}
