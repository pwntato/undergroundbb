// A comment's plaintext layout (#44), the bytes AES-GCM seals under the group key.
// Binary and length-prefixed like a post's (post.ts), for the same reason: the
// server caps a comment's size from the ciphertext alone. Layout:
//
//   version (1 byte, 0x01)
//   u32 BE length, text (UTF-8)
//   u32 BE length, at: the exact write time, RFC 3339 UTC with milliseconds
//
// The overhead is 1 + 2 * 4 + 24 = 33 bytes, plus the 16-byte GCM tag
// (handlers.commentMinCiphertext is the empty comment). The exact time lives
// only in here; the row carries just the signed day. This must not change once
// a real comment exists under it.
//
// An EDITED comment (#45) is version 0x02: the same two fields, then
//
//   u32 BE length, edited_at: when this edition was written, same format as at
//
// `at` stays the original write time; the 28 extra bytes are the room the
// server gives an edit (handlers.editedAtOverhead, post.ts EDITED_AT_BYTES).
// Only an edit writes version 2, and the "edited" marker comes from this field
// alone. The day checks are the reader's (comment-check.ts).

export const COMMENT_VERSION = 1

/** The version byte of an edited comment: version 1's fields plus edited_at. */
export const COMMENT_EDITED_VERSION = 2

/** Bytes a comment adds around its text, before the GCM tag. */
export const COMMENT_ENVELOPE_BYTES = 1 + 2 * 4 + 24

export interface CommentContent {
  readonly text: string
  /** RFC 3339 UTC with milliseconds, e.g. 2026-10-28T12:34:56.789Z (24 bytes). */
  readonly at: string
  /** Present only on an edited comment (version 2): when this edition was written. */
  readonly editedAt?: string
}

const AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

export function encodeComment(content: CommentContent): Uint8Array {
  if (!AT_PATTERN.test(content.at)) {
    throw new Error('comment: at must be an RFC 3339 UTC time with milliseconds')
  }
  const edited = content.editedAt !== undefined
  if (edited && !AT_PATTERN.test(content.editedAt)) {
    throw new Error('comment: editedAt must be an RFC 3339 UTC time with milliseconds')
  }
  const enc = new TextEncoder()
  const fields = [enc.encode(content.text), enc.encode(content.at)]
  if (edited) fields.push(enc.encode(content.editedAt))
  const out = new Uint8Array(1 + fields.reduce((n, f) => n + 4 + f.length, 0))
  const view = new DataView(out.buffer)
  out[0] = edited ? COMMENT_EDITED_VERSION : COMMENT_VERSION
  let offset = 1
  for (const f of fields) {
    view.setUint32(offset, f.length)
    out.set(f, offset + 4)
    offset += 4 + f.length
  }
  return out
}

/** Reads a comment back; throws on any deviation from the layout rather than guessing. */
export function decodeComment(bytes: Uint8Array): CommentContent {
  const count =
    bytes[0] === COMMENT_VERSION ? 2 : bytes[0] === COMMENT_EDITED_VERSION ? 3 : undefined
  if (count === undefined || bytes.length < 1 + count * 4) {
    throw new Error('comment: unknown or truncated layout')
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const dec = new TextDecoder('utf-8', { fatal: true })
  const fields: string[] = []
  let offset = 1
  for (let i = 0; i < count; i++) {
    if (offset + 4 > bytes.length) {
      throw new Error('comment: truncated')
    }
    const len = view.getUint32(offset)
    offset += 4
    if (len > bytes.length - offset) {
      throw new Error('comment: field runs past the end')
    }
    fields.push(dec.decode(bytes.subarray(offset, offset + len)))
    offset += len
  }
  if (offset !== bytes.length) {
    throw new Error('comment: trailing bytes')
  }
  const [text, at, editedAt] = fields as [string, string, string | undefined]
  if (!AT_PATTERN.test(at) || (editedAt !== undefined && !AT_PATTERN.test(editedAt))) {
    throw new Error('comment: malformed time')
  }
  return editedAt === undefined ? { text, at } : { text, at, editedAt }
}
