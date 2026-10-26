// The caller's own signing-key history, verified -- issue #62, docs/DESIGN.md
// "Key rotation" ("A pin and a verification record carry the day, and rotation
// re-signs neither").
//
// A pin or a verification record the caller signed before rotating is signed
// under a SUPERSEDED key, and the server stores and serves those rows, so the
// signature alone proves nothing: an operator holding a leaked old key could
// write one dated inside that key's interval. Such a row counts only if
//
//   - the key is one the caller's verified KEYCHANGE# chain says they held,
//   - the signed day falls inside that key's interval (up to the rotation that
//     replaced it, and after the rotation that introduced it), and
//   - the row's id (SHA-256(SK || signature), truncated) is in the roster the
//     caller listed under that rotation, whose digest both keys signed.
//
// The chain itself is trusted only if every link verifies under both keys it
// names, each link's old key is the previous link's new key, and the last
// link's new key is the key the caller unwrapped themselves (`ownSigningKey`,
// from the worker): a fork an operator signs with a leaked old key ends at a
// key of its own, never at the caller's.
//
// Pure and never throws; a history that does not verify is null, and callers
// then accept only the caller's current key, which fails closed.

import { base64ToBytes, bytesToBase64 } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import { keyRotationPayload, rosterDigest, rosterEntryId } from './key-rotation.js'

const KEY_SIZE = 32
const SIGNATURE_SIZE = 64
const ROSTER_ENTRY_SIZE = 16

/** One KEYCHANGE# row as served by GET /api/users/{id} (all binary fields base64). */
export interface WireKeyChange {
  readonly keyEpoch: number
  readonly day: string
  readonly oldSigningPublicKey: string
  readonly oldWrappingPublicKey: string
  readonly newSigningPublicKey: string
  readonly newWrappingPublicKey: string
  readonly rosterDigest: string
  readonly oldSignature: string
  readonly newSignature: string
}

/** One rotation's roster as served to its owner on the first page of GET /api/pins. */
export interface WireKeyChangeRoster {
  readonly keyEpoch: number
  readonly roster: readonly string[]
}

export interface OwnKeyLink {
  /** The KeyEpoch this rotation produced (1 for the first). */
  readonly epoch: number
  /** The UTC day the rotation was signed. */
  readonly day: string
  readonly oldSigning: Uint8Array
  readonly newSigning: Uint8Array
  readonly oldWrapping: Uint8Array
  readonly newWrapping: Uint8Array
  /** The listed rows whose digest matched the signed one; null when the list was missing or did not match. */
  readonly roster: readonly Uint8Array[] | null
}

export interface OwnKeyHistory {
  /** The caller's current signing key: the one the chain ends at. */
  readonly current: Uint8Array
  readonly links: readonly OwnKeyLink[]
}

function decode(b64: string, size: number): Uint8Array | null {
  try {
    const b = base64ToBytes(b64)
    return b.length === size ? b : null
  } catch {
    return null
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

function isDay(s: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(`${s}T00:00:00Z`))
}

function decodeRoster(
  roster: readonly string[] | undefined,
  digest: Uint8Array,
): readonly Uint8Array[] | null {
  if (roster === undefined) return null
  const entries: Uint8Array[] = []
  for (const e of roster) {
    const b = decode(e, ROSTER_ENTRY_SIZE)
    if (b === null) return null
    entries.push(b)
  }
  return sameBytes(rosterDigest(entries), digest) ? entries : null
}

/**
 * Verifies the served chain and returns the history, or null when anything
 * about the chain fails to verify. An empty chain is a history with no links:
 * an account that never rotated. `ownSigningKey` must be the key the caller
 * holds; whether the SERVED current key equals it is the caller's check.
 */
export function buildOwnKeyHistory(input: {
  readonly userId: string
  readonly ownSigningKey: Uint8Array
  readonly changes: readonly WireKeyChange[]
  readonly rosters: readonly WireKeyChangeRoster[]
}): OwnKeyHistory | null {
  const { userId, ownSigningKey, rosters } = input
  const changes = [...input.changes].sort((a, b) => a.keyEpoch - b.keyEpoch)
  const links: OwnKeyLink[] = []
  let previous: OwnKeyLink | undefined
  for (const [i, c] of changes.entries()) {
    // Epochs run 1..n with no gap: a hidden middle link would break the chain.
    if (c.keyEpoch !== i + 1 || !isDay(c.day)) return null
    const oldSigning = decode(c.oldSigningPublicKey, KEY_SIZE)
    const oldWrapping = decode(c.oldWrappingPublicKey, KEY_SIZE)
    const newSigning = decode(c.newSigningPublicKey, KEY_SIZE)
    const newWrapping = decode(c.newWrappingPublicKey, KEY_SIZE)
    const digest = decode(c.rosterDigest, 32)
    const oldSig = decode(c.oldSignature, SIGNATURE_SIZE)
    const newSig = decode(c.newSignature, SIGNATURE_SIZE)
    if (!oldSigning || !oldWrapping || !newSigning || !newWrapping) return null
    if (!digest || !oldSig || !newSig) return null
    // The payload carries the epoch BEFORE the rotation.
    const payload = keyRotationPayload(
      userId,
      oldSigning,
      oldWrapping,
      newSigning,
      newWrapping,
      c.day,
      c.keyEpoch - 1,
      digest,
    )
    if (!verify(oldSigning, SigningContext.KeyRotation, payload, oldSig)) return null
    if (!verify(newSigning, SigningContext.KeyRotation, payload, newSig)) return null
    if (previous !== undefined) {
      if (!sameBytes(previous.newSigning, oldSigning)) return null
      if (!sameBytes(previous.newWrapping, oldWrapping)) return null
      if (c.day < previous.day) return null
    }
    const listed = rosters.find((r) => r.keyEpoch === c.keyEpoch)
    const link: OwnKeyLink = {
      epoch: c.keyEpoch,
      day: c.day,
      oldSigning,
      newSigning,
      oldWrapping,
      newWrapping,
      roster: decodeRoster(listed?.roster, digest),
    }
    links.push(link)
    previous = link
  }
  if (previous !== undefined && !sameBytes(previous.newSigning, ownSigningKey)) return null
  return { current: ownSigningKey, links }
}

/**
 * Whether a verified chain carries the key pair an admission names to the
 * pair the server serves now (#62, DESIGN.md "Roles and the chain of trust"
 * (5)). The admitted pair must be some link's OLD pair, the record must not be
 * dated after that rotation (nor before the one that introduced the pair; both
 * keys are candidates on a rotation day), and the last link must end at the
 * served wrapping key (the signing end is the history's `current`, which the
 * builder already tied to the served signing key). A rotated member's old
 * admission then still counts; the chain only ever says the served keys were
 * introduced by a holder of the admitted ones, never that anyone approved them.
 */
export function chainCarriesKeys(
  history: OwnKeyHistory,
  admittedSigning: Uint8Array,
  admittedWrapping: Uint8Array,
  admissionDay: string,
  servedWrapping: Uint8Array,
): boolean {
  if (!isDay(admissionDay)) return false
  const last = history.links[history.links.length - 1]
  if (last === undefined || !sameBytes(last.newWrapping, servedWrapping)) return false
  return history.links.some((link, i) => {
    if (!sameBytes(link.oldSigning, admittedSigning)) return false
    if (!sameBytes(link.oldWrapping, admittedWrapping)) return false
    if (admissionDay > link.day) return false
    const introduced = i > 0 ? history.links[i - 1]!.day : undefined
    return introduced === undefined || admissionDay >= introduced
  })
}

/** Every signing key the history says the caller held: the current one, then each superseded one. */
export function ownKeys(history: OwnKeyHistory): Uint8Array[] {
  return [history.current, ...history.links.map((l) => l.oldSigning)]
}

/**
 * Whether a PIN#/VERIFIED# row signed by `signer` on `signedDay` counts as the
 * caller's. `sk` is the row's sort key ("PIN#<uuid>" or "VERIFIED#<uuid>").
 * The signature itself is checked by the caller; this decides whether the
 * signer may be trusted at all.
 */
export function ownSignerAccepted(
  history: OwnKeyHistory,
  signer: Uint8Array,
  signedDay: string,
  sk: string,
  signature: Uint8Array,
): boolean {
  if (sameBytes(signer, history.current)) return true
  if (!isDay(signedDay)) return false
  const id = rosterEntryId(sk, signature)
  return history.links.some((link, i) => {
    if (!sameBytes(link.oldSigning, signer)) return false
    // Both keys are candidates on the rotation day itself (day resolution).
    if (signedDay > link.day) return false
    const introduced = i > 0 ? history.links[i - 1]!.day : undefined
    if (introduced !== undefined && signedDay < introduced) return false
    return link.roster?.some((e) => sameBytes(e, id)) === true
  })
}

/**
 * Whether the projection the server serves for the caller agrees with the
 * verified history: the same current key, the same set of superseded keys, and
 * a KeyEpoch equal to the number of rotations. The served superseded list is
 * unsigned, so this is what ties it to the signed chain.
 */
export function ownHistoryMatchesServed(
  history: OwnKeyHistory,
  served: {
    readonly signingPublicKey: string
    readonly supersededSigningKeys: readonly { readonly publicKey: string }[]
    readonly keyEpoch: number
  },
): boolean {
  const current = decode(served.signingPublicKey, KEY_SIZE)
  if (current === null || !sameBytes(current, history.current)) return false
  if (served.keyEpoch !== history.links.length) return false
  if (served.supersededSigningKeys.length !== history.links.length) return false
  return history.links.every((link) =>
    served.supersededSigningKeys.some((k) => {
      const key = decode(k.publicKey, KEY_SIZE)
      return key !== null && sameBytes(key, link.oldSigning)
    }),
  )
}

/**
 * The caller's key history as the grant and removal verifiers read it
 * (grant-chain's UserKeyHistory), built from the verified chain and not from
 * the served projection: the served `from`/`until` intervals are unsigned, so a
 * server holding a leaked old key could widen its interval past the rotation
 * and have grants dated afterwards verify under it (and push the current key
 * out of those days). Each old key ends on its link's signed day and starts on
 * the previous link's; the first key has no signed start, so it is open below,
 * as ownSignerAccepted treats it.
 */
export function ownKeyHistoryForVerifiers(history: OwnKeyHistory): {
  readonly signingPublicKey: string
  readonly supersededSigningKeys: readonly {
    readonly publicKey: string
    readonly from: string
    readonly until: string
  }[]
} {
  return {
    signingPublicKey: bytesToBase64(history.current),
    supersededSigningKeys: history.links.map((link, i) => ({
      publicKey: bytesToBase64(link.oldSigning),
      from: i > 0 ? history.links[i - 1]!.day : '1970-01-01',
      until: link.day,
    })),
  }
}
