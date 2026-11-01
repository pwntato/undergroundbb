// A post's plaintext layout (#42), the bytes AES-GCM seals under the group key.
//
// Binary and length-prefixed, not JSON, so the server can cap a post's size
// from the ciphertext alone: JSON escaping can inflate a byte up to six times
// (\u0000), which would force a limit loose enough to defeat the cap. Layout:
//
//   version (1 byte, 0x01)
//   u32 BE length, title (UTF-8)
//   u32 BE length, body (UTF-8)
//   u32 BE length, at: the exact write time, RFC 3339 UTC with milliseconds
//
// The exact time lives only in here: the sort key discloses the day and
// nothing finer. The overhead is 1 + 3 * 4 + 24 = 37 bytes, plus the 16-byte
// GCM tag; the server's limit (handlers.postEnvelopeOverhead, 64) sits just
// above that. This must not change once a real post exists under it.
//
// An EDITED post (#45) is version 0x02: the same three fields, then
//
//   u32 BE length, edited_at: when this edition was written, same format as at
//
// `at` stays the original write time. The extra field is 4 + 24 = 28 bytes,
// exactly the room the server gives an edit (handlers.editedAtOverhead). Only
// an edit writes version 2, and the "edited" marker a reader shows comes from
// this field alone, never from the row. Whether edited_at is on the day the
// edit was signed is the reader's check (post-check.ts), not the decoder's.

export const POST_VERSION = 1

/** The version byte of an edited post: version 1's fields plus edited_at. */
export const POST_EDITED_VERSION = 2

/** Bytes edited_at adds to an item; keep equal to handlers.editedAtOverhead. */
export const EDITED_AT_BYTES = 4 + 24

/** Bytes a post adds around its title and body, before the GCM tag. */
export const POST_ENVELOPE_BYTES = 1 + 3 * 4 + 24

/** The AES-GCM tag appended to every ciphertext. */
export const GCM_TAG_BYTES = 16

/** The longest ciphertext overhead the server tolerates; keep equal to handlers.postEnvelopeOverhead. */
export const SERVER_ENVELOPE_ALLOWANCE = 64

export interface PostContent {
  readonly title: string
  readonly body: string
  /** RFC 3339 UTC with milliseconds, e.g. 2026-10-28T12:34:56.789Z (24 bytes). */
  readonly at: string
  /** Present only on an edited post (version 2): when this edition was written, same format as `at`. */
  readonly editedAt?: string
}

const AT_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

/** UTF-8 byte length of s, the unit the size caps count in. */
export function utf8Length(s: string): number {
  return new TextEncoder().encode(s).length
}

export function encodePost(content: PostContent): Uint8Array {
  if (!AT_PATTERN.test(content.at)) {
    throw new Error('post: at must be an RFC 3339 UTC time with milliseconds')
  }
  const edited = content.editedAt !== undefined
  if (edited && !AT_PATTERN.test(content.editedAt)) {
    throw new Error('post: editedAt must be an RFC 3339 UTC time with milliseconds')
  }
  const enc = new TextEncoder()
  const fields = [enc.encode(content.title), enc.encode(content.body), enc.encode(content.at)]
  if (edited) fields.push(enc.encode(content.editedAt))
  const out = new Uint8Array(1 + fields.reduce((n, f) => n + 4 + f.length, 0))
  const view = new DataView(out.buffer)
  out[0] = edited ? POST_EDITED_VERSION : POST_VERSION
  let offset = 1
  for (const f of fields) {
    view.setUint32(offset, f.length)
    out.set(f, offset + 4)
    offset += 4 + f.length
  }
  return out
}

/** Reads a post back; throws on any deviation from the layout rather than guessing. */
export function decodePost(bytes: Uint8Array): PostContent {
  const count = bytes[0] === POST_VERSION ? 3 : bytes[0] === POST_EDITED_VERSION ? 4 : undefined
  if (count === undefined || bytes.length < 1 + count * 4) {
    throw new Error('post: unknown or truncated layout')
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const dec = new TextDecoder('utf-8', { fatal: true })
  const fields: string[] = []
  let offset = 1
  for (let i = 0; i < count; i++) {
    if (offset + 4 > bytes.length) {
      throw new Error('post: truncated')
    }
    const len = view.getUint32(offset)
    offset += 4
    if (len > bytes.length - offset) {
      throw new Error('post: field runs past the end')
    }
    fields.push(dec.decode(bytes.subarray(offset, offset + len)))
    offset += len
  }
  if (offset !== bytes.length) {
    throw new Error('post: trailing bytes')
  }
  const [title, body, at, editedAt] = fields as [string, string, string, string | undefined]
  if (!AT_PATTERN.test(at) || (editedAt !== undefined && !AT_PATTERN.test(editedAt))) {
    throw new Error('post: malformed time')
  }
  return editedAt === undefined ? { title, body, at } : { title, body, at, editedAt }
}

/** The ciphertext length a post of these field sizes produces. */
export function postCiphertextLength(titleBytes: number, bodyBytes: number): number {
  return titleBytes + bodyBytes + POST_ENVELOPE_BYTES + GCM_TAG_BYTES
}
