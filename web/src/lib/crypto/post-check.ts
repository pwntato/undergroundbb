// Checking a stored post -- #43, docs/DESIGN.md "For the reader". Two facts the
// server cannot give a reader, and one it must not be trusted with:
//
//   - The signature: it covers the author, group, sort key, generation, day and
//     ciphertext (crypto.SignedPayload), and is checked under the author's
//     signing keys for the sort key's day: their current key from the day it
//     was introduced, and each superseded key up to the rotation that ended it
//     (both on a rotation day). It does not cover the nonce, so a post that
//     fails to OPEN says nothing about its author (see openPosts), but one
//     whose signature fails is not by the key set it claims.
//   - The time: the decrypted `at` is whatever the author signed, so a post is
//     suspect when it does not fall on the sort key's UTC day.
//   - The author's keys are what the server serves, so the caller anchors them
//     to a key it already trusts before calling this (routes/runListPosts);
//     a leaked superseded key can sign a post dated anywhere in that key's
//     interval and it verifies, the same accepted limit as a wrap record.
//
// Pure and never throws.

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import { buildOwnKeyHistory, signingKeysOn, type WireKeyChange } from './own-history.js'
import { signedPayload } from './payload.js'

/** The author's served current signing key and key-change chain. */
export interface AuthorKeys {
  readonly signingPublicKey: string
  readonly keyChanges: readonly WireKeyChange[]
}

export type SignatureVerdict =
  | { readonly kind: 'valid' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'unchecked'; readonly reason: string }

const SORT_KEY = /^POST#(\d{4}-\d{2}-\d{2})#[0-9a-f]{16}$/

/** The UTC day a post sort key carries, or undefined for a malformed key. */
export function sortKeyDay(sortKey: string): string | undefined {
  return SORT_KEY.exec(sortKey)?.[1]
}

/**
 * A post's full address, `<gid>#<YYYY-MM-DD>#<16 hex>`: what comments and
 * reactions are keyed and bound under. The reverse of the server's
 * idgen.ParsePostID; undefined for a sort key that is not a post's.
 */
export function postIdOf(groupId: string, sortKey: string): string | undefined {
  return SORT_KEY.test(sortKey) ? `${groupId}#${sortKey.slice('POST#'.length)}` : undefined
}

/** Whether a decrypted RFC 3339 `at` falls on the sort key's UTC day. */
export function atOnSortKeyDay(sortKey: string, at: string): boolean {
  const day = sortKeyDay(sortKey)
  return day !== undefined && at.slice(0, 10) === day
}

export function checkPostSignature(input: {
  readonly groupId: string
  readonly authorUserId: string
  readonly sortKey: string
  readonly generation: number
  readonly ciphertext: string
  readonly signature: string
  /** Absent until the author's keys have been read and anchored. */
  readonly author: AuthorKeys | undefined
}): SignatureVerdict {
  const day = sortKeyDay(input.sortKey)
  if (day === undefined) return { kind: 'invalid' }
  return checkSignedItem({ ...input, day, context: SigningContext.Post })
}

/**
 * The check a post and a comment share: the signature covers the author, group,
 * sort key, generation, signing day and ciphertext under `context`, and is tried
 * under each signing key the author held on `day`. A post's day is the one in
 * its sort key; a comment's is stored beside it (routes/runLoadThread).
 */
export function checkSignedItem(input: {
  readonly groupId: string
  readonly authorUserId: string
  readonly sortKey: string
  readonly generation: number
  readonly ciphertext: string
  readonly signature: string
  readonly day: string
  readonly context: SigningContext
  readonly author: AuthorKeys | undefined
}): SignatureVerdict {
  const { day } = input
  if (input.author === undefined) {
    return { kind: 'unchecked', reason: 'their keys were not read' }
  }
  let signature: Uint8Array
  let ciphertext: Uint8Array
  let current: Uint8Array
  try {
    signature = base64ToBytes(input.signature)
    ciphertext = base64ToBytes(input.ciphertext)
    current = base64ToBytes(input.author.signingPublicKey)
  } catch {
    return { kind: 'unchecked', reason: 'the post or the keys served for its author are malformed' }
  }
  const history = buildOwnKeyHistory({
    userId: input.authorUserId,
    ownSigningKey: current,
    changes: input.author.keyChanges,
    rosters: [],
  })
  if (history === null) {
    return { kind: 'unchecked', reason: 'their key history does not verify' }
  }
  const payload = signedPayload(
    input.authorUserId,
    input.groupId,
    input.sortKey,
    input.generation,
    day,
    ciphertext,
  )
  return signingKeysOn(history, current, day).some((k) =>
    verify(k, input.context, payload, signature),
  )
    ? { kind: 'valid' }
    : { kind: 'invalid' }
}
