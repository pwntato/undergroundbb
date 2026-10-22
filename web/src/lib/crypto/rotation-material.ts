// The worker-side half of a key rotation (#62, docs/DESIGN.md "What a rotation
// writes"). Pure functions over the live keys, like credential-material.ts, so
// they can be unit-tested; worker.ts holds the pending state between calls.
//
// The order the flow needs, and why each step is its own call:
//   1. beginKeyRotation mints the NEW keypairs. They exist only in the worker.
//   2. wrapHandoff, once per administered group, wraps the group's current key
//      (opened with the OLD wrapping key) to the NEW public key. These rows
//      are what lets the self re-key survive a closed tab, so they are written
//      before rotate-keys.
//   3. signKeyRotation signs once with each key and re-wraps the new keys under
//      a new password and a new recovery code.
//   4. commitKeyRotation swaps the live keys to the new ones, only after the
//      server accepted the rotation.

import { base64ToBytes, bytesToBase64 } from './base64.js'
import {
  toWireWrapped,
  unwrapOwnGroupKey,
  wrapNewCredentials,
  type LiveKeys,
  type ProgressStep,
  type WireWrapped,
} from './credential-material.js'
import * as ed25519 from './ed25519.js'
import { encodeKeyBundle } from './keybundle.js'
import { handoffWrapAAD, keyRotationPayload, rosterDigest } from './key-rotation.js'
import type { RecoveryMaterial } from './worker-protocol.js'
import { generateWrappingKey, wrap, type Wrapped, type WrappingKey } from './x25519.js'

/** The new keypairs of a rotation that has begun and not yet committed. */
export interface PendingRotation {
  readonly userId: string
  readonly signingKey: ed25519.SigningKey
  readonly wrappingKey: WrappingKey
}

/** The roster entry ids are 16 bytes (crypto.RosterEntryID). */
const ROSTER_ENTRY_SIZE = 16
/** The server's cap on a roster (maxRotationRoster). */
export const MAX_ROSTER_ENTRIES = 8192

export function beginKeyRotation(keys: LiveKeys): {
  pending: PendingRotation
  newSigningPublicKey: string
  newWrappingPublicKey: string
} {
  const signingKey = ed25519.generateSigningKey()
  const wrappingKey = generateWrappingKey()
  return {
    pending: { userId: keys.userId, signingKey, wrappingKey },
    newSigningPublicKey: bytesToBase64(signingKey.publicKey),
    newWrappingPublicKey: bytesToBase64(wrappingKey.publicKey),
  }
}

export interface WrapHandoffRequest {
  readonly groupId: string
  /** The caller's own entry point in the group and the generation it is at. */
  readonly ownWrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
  readonly generation: number
}

export interface HandoffWrap {
  readonly generation: number
  readonly newWrappingPublicKey: string
  readonly wrappedGroupKey: WireWrapped
}

/**
 * The group's current key, opened with the OLD wrapping key and wrapped to the
 * NEW public key under handoffWrapAAD, which binds user, group, generation and
 * the key it is wrapped to. The plaintext key never leaves this function.
 */
export async function wrapHandoff(
  keys: LiveKeys,
  pending: PendingRotation,
  req: WrapHandoffRequest,
): Promise<HandoffWrap> {
  const own: Wrapped = {
    ephemeralPub: base64ToBytes(req.ownWrappedGroupKey.ephemeralPub),
    nonce: base64ToBytes(req.ownWrappedGroupKey.nonce),
    ciphertext: base64ToBytes(req.ownWrappedGroupKey.ciphertext),
  }
  const groupKey = await unwrapOwnGroupKey(keys, req.groupId, own, req.generation)
  const wrapped = await wrap(
    pending.wrappingKey.publicKey,
    groupKey,
    handoffWrapAAD(keys.userId, req.groupId, req.generation, pending.wrappingKey.publicKey),
  )
  return {
    generation: req.generation,
    newWrappingPublicKey: bytesToBase64(pending.wrappingKey.publicKey),
    wrappedGroupKey: toWireWrapped(wrapped),
  }
}

export interface SignKeyRotationRequest {
  readonly newPassword: string
  /** The account's KeyEpoch the server holds; signed into the payload. */
  readonly expectedKeyEpoch: number
  /** Base64 RosterEntryID of every PIN# and VERIFIED# row the caller has. */
  readonly roster: readonly string[]
}

export interface SignedKeyRotation {
  readonly signedDay: string
  readonly newSigningPublicKey: string
  readonly newWrappingPublicKey: string
  readonly roster: readonly string[]
  readonly oldSignature: string
  readonly newSignature: string
  /** The new password's and new recovery code's wraps of the NEW keys. */
  readonly credentials: RecoveryMaterial
}

export class RosterTooLargeError extends Error {
  constructor() {
    super(`rotation: a roster holds at most ${MAX_ROSTER_ENTRIES} entries`)
    this.name = 'RosterTooLargeError'
  }
}

/**
 * Signs the rotation under both keys and re-wraps the new keys under the new
 * password and a fresh recovery code (credentials.recoveryCode is shown to the
 * user once and never sent to the server). The roster the digest covers is
 * the caller's own pin and verification rows; the server stores the list and
 * serves it back to the owner only.
 */
export async function signKeyRotation(
  keys: LiveKeys,
  pending: PendingRotation,
  req: SignKeyRotationRequest,
  onProgress: (step: ProgressStep) => void,
  now: Date = new Date(),
): Promise<SignedKeyRotation> {
  if (req.roster.length > MAX_ROSTER_ENTRIES) {
    throw new RosterTooLargeError()
  }
  const entries = req.roster.map((e) => {
    const b = base64ToBytes(e)
    if (b.length !== ROSTER_ENTRY_SIZE) {
      throw new Error('rotation: a roster entry must be 16 bytes')
    }
    return b
  })
  const signedDay = now.toISOString().slice(0, 10)
  const payload = keyRotationPayload(
    keys.userId,
    keys.signingKey.publicKey,
    keys.wrappingKey.publicKey,
    pending.signingKey.publicKey,
    pending.wrappingKey.publicKey,
    signedDay,
    req.expectedKeyEpoch,
    rosterDigest(entries),
  )
  const oldSignature = ed25519.sign(keys.signingKey, ed25519.SigningContext.KeyRotation, payload)
  const newSignature = ed25519.sign(pending.signingKey, ed25519.SigningContext.KeyRotation, payload)

  const bundle = encodeKeyBundle({
    signingSeed: pending.signingKey.seed,
    wrappingPrivateKey: pending.wrappingKey.privateKey,
  })
  const credentials = await wrapNewCredentials(keys.userId, req.newPassword, bundle, onProgress)

  return {
    signedDay,
    newSigningPublicKey: bytesToBase64(pending.signingKey.publicKey),
    newWrappingPublicKey: bytesToBase64(pending.wrappingKey.publicKey),
    roster: req.roster,
    oldSignature: bytesToBase64(oldSignature),
    newSignature: bytesToBase64(newSignature),
    credentials,
  }
}

/** The live keys after the server accepted the rotation. */
export function commitKeyRotation(pending: PendingRotation): LiveKeys {
  return {
    userId: pending.userId,
    signingKey: pending.signingKey,
    wrappingKey: pending.wrappingKey,
  }
}

/**
 * The worker's pending rotation. Held in a class, not a bare variable in
 * worker.ts, so the rules around it (one account, refuse pins while it is set)
 * can be tested: worker.ts itself cannot be imported outside a worker.
 */
export class RotationState {
  private pending: PendingRotation | null = null

  /** Starts (or restarts) a rotation, dropping any unfinished attempt's keys. */
  begin(pending: PendingRotation): void {
    this.pending = pending
  }

  /** The pending rotation for userId; throws if none has begun for that account. */
  require(userId: string): PendingRotation {
    if (this.pending === null || this.pending.userId !== userId) {
      throw new Error('worker: no key rotation has begun for this account')
    }
    return this.pending
  }

  /**
   * Throws while a rotation is in flight. A pin or verification signed then
   * would be signed under a key about to be replaced and would miss the roster
   * the rotation signs over (docs/DESIGN.md, "What a key change looks like to
   * others").
   */
  assertIdle(what: string): void {
    if (this.pending !== null) {
      throw new Error(
        `worker: a key rotation is in progress -- finish or cancel it before you ${what}`,
      )
    }
  }

  /** The server accepted the rotation: returns the new live keys and clears the state. */
  commit(userId: string): LiveKeys {
    const keys = commitKeyRotation(this.require(userId))
    this.pending = null
    return keys
  }

  /** Drops the new keys (a cancelled or failed rotation, or a logout). */
  clear(): void {
    this.pending = null
  }
}
