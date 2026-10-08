// Client-side check of a group's removal history (#178). Pure: no fetching, no
// clock. Every removal that rotated the key left a signed record on the
// durable GENKEY# chain link for the generation it replaced (the remover's
// signature over rotationStartPayload for (group, remover, removed, n+1)).
// Links are contiguous, so a caller that holds generation G (authenticated by
// the AAD of its own wrapped key) requires a verifying record for EVERY n < G.
// A withheld, blanked or forged record is then a gap and the check fails,
// rather than the removed member quietly passing as never having been removed.
//
// What the result is for: a member removed at generation g is only a valid
// recipient again if their admission was signed at generation g or later (a
// fresh invite after the removal). The caller applies that rule; this module
// only produces the map of who was removed, and when.
//
// Known limits: the remover's keys come from the server (pin-checked by the
// caller), a record can only be forged to EXCLUDE someone, never to include
// them, so a first-sight key is accepted as in the rest of the rotation
// checks; and a remover whose keys can no longer be read stops the check
// (fail closed, the same liveness cost the rotation marker's own record has).

import { base64ToBytes } from './base64.js'
import { SigningContext, verify } from './ed25519.js'
import { rotationStartPayload } from './group.js'

/** One chain link as served by GET /api/groups/{id}/keychain. */
export interface RemovalLink {
  /** The generation whose key the link wraps; the removal minted generation + 1. */
  readonly generation: number
  readonly removerUserId?: string
  readonly removedUserId?: string
  /** Base64 Ed25519 signature under SigningContext.RotationStart. */
  readonly startSignature?: string
}

export type RemovalVerdict =
  | {
      readonly ok: true
      /**
       * For every user removed at least once, the newest generation a removal
       * minted (the link's generation + 1). Their admission must be signed at
       * this generation or later to count.
       */
      readonly removedAt: ReadonlyMap<string, number>
    }
  | { readonly ok: false; readonly reason: string }

export interface VerifyRemovalsInput {
  readonly groupId: string
  /** The caller's own generation: links 0..currentGeneration-1 must all be present. */
  readonly currentGeneration: number
  readonly links: readonly RemovalLink[]
  /**
   * Every signing key now served for a user (current and superseded), or null
   * if they could not be read. Must be pin-checked by the caller.
   */
  readonly keysFor: (userId: string) => readonly Uint8Array[] | null
}

/** The removers whose keys verifyRemovals will ask for, so the caller can fetch them in one batch. */
export function removersOf(links: readonly RemovalLink[]): string[] {
  return [
    ...new Set(links.flatMap((l) => (l.removerUserId === undefined ? [] : [l.removerUserId]))),
  ]
}

function fail(reason: string): RemovalVerdict {
  return { ok: false, reason }
}

/** Never throws on malformed input. */
export function verifyRemovals(input: VerifyRemovalsInput): RemovalVerdict {
  const { groupId, currentGeneration, links } = input
  if (!Number.isSafeInteger(currentGeneration) || currentGeneration < 0) {
    return fail('the group key generation is malformed')
  }
  const byGeneration = new Map<number, RemovalLink>()
  for (const link of links) {
    if (!Number.isSafeInteger(link.generation) || link.generation < 0) {
      return fail('a key chain link has a malformed generation')
    }
    if (byGeneration.has(link.generation)) {
      return fail('the key chain lists a generation twice')
    }
    byGeneration.set(link.generation, link)
  }

  const removedAt = new Map<string, number>()
  for (let n = 0; n < currentGeneration; n++) {
    const link = byGeneration.get(n)
    if (link === undefined) {
      return fail(`the key chain is missing the removal that created generation ${String(n + 1)}`)
    }
    const { removerUserId, removedUserId, startSignature } = link
    if (
      removerUserId === undefined ||
      removedUserId === undefined ||
      startSignature === undefined
    ) {
      return fail(
        `generation ${String(n + 1)} was created without a signed record of who was removed`,
      )
    }
    let signature: Uint8Array
    try {
      signature = base64ToBytes(startSignature)
    } catch {
      return fail(`the signed removal record for generation ${String(n + 1)} is malformed`)
    }
    const keys = input.keysFor(removerUserId)
    if (keys === null) {
      return fail(
        `could not read the keys of ${removerUserId}, who removed a member at generation ${String(n + 1)}`,
      )
    }
    const payload = rotationStartPayload(groupId, removerUserId, removedUserId, n + 1)
    if (!keys.some((k) => verify(k, SigningContext.RotationStart, payload, signature))) {
      return fail(`the signed removal record for generation ${String(n + 1)} does not verify`)
    }
    removedAt.set(removedUserId, n + 1) // ascending n, so the newest wins
  }
  return { ok: true, removedAt }
}
