// Checking a stored comment -- #44, docs/DESIGN.md "Comments (#44)". The same two
// facts as for a post (post-check.ts), with the day coming from the row rather
// than the sort key, because a comment's sort key (`CMT#<path>`) has none:
//
//   - The signature covers the author, group, `CMT#<path>`, generation, the
//     signed day on the row and the ciphertext, under ContextComment, and is
//     checked under the author's signing keys for that day. The post's address
//     is NOT in it: the ciphertext's AAD binds the post (commentAAD), so a
//     comment moved under another post fails to OPEN, which says nothing about
//     its author (the nonce is not signed).
//   - The time: the decrypted `at` is whatever the author signed, so a comment is
//     suspect when it does not fall on the signed day.
//
// Pure and never throws.

import { SigningContext } from './ed25519.js'
import { checkSignedItem, type AuthorKeys, type SignatureVerdict } from './post-check.js'

const DAY = /^\d{4}-\d{2}-\d{2}$/

/** Whether a decrypted RFC 3339 `at` falls on the comment's signed UTC day. */
export function atOnSignedDay(signedDay: string, at: string): boolean {
  return DAY.test(signedDay) && at.slice(0, 10) === signedDay
}

export function checkCommentSignature(input: {
  readonly groupId: string
  readonly authorUserId: string
  readonly path: string
  readonly generation: number
  readonly signedDay: string
  readonly ciphertext: string
  readonly signature: string
  /** Absent until the author's keys have been read and anchored. */
  readonly author: AuthorKeys | undefined
}): SignatureVerdict {
  if (!DAY.test(input.signedDay)) return { kind: 'invalid' }
  return checkSignedItem({
    groupId: input.groupId,
    authorUserId: input.authorUserId,
    sortKey: `CMT#${input.path}`,
    generation: input.generation,
    ciphertext: input.ciphertext,
    signature: input.signature,
    day: input.signedDay,
    context: SigningContext.Comment,
    author: input.author,
  })
}
