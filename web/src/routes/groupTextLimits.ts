// The name and description limits shared by the create-group and settings
// forms (#152). The server bounds them in UTF-8 bytes (Go's len), not
// characters: 150 accented or CJK characters pass a UTF-16 `String.length`
// check and are then rejected server-side (PR #151 review). The same limits
// apply to private groups, whose text is encrypted client-side: a description
// within 2000 bytes encrypts to well under the server's ciphertext bound.

export const MAX_NAME_LENGTH = 200
export const MAX_DESCRIPTION_LENGTH = 2000

export const utf8Length = (text: string): number => new TextEncoder().encode(text).length

/** The error to show for a name or description over the byte limits, or null if both fit. */
export function groupTextLengthError(name: string, description: string): string | null {
  if (utf8Length(name) > MAX_NAME_LENGTH) {
    return `Group name is too long. The limit is ${String(MAX_NAME_LENGTH)} bytes, and accented or non-Latin characters take more than one.`
  }
  if (utf8Length(description) > MAX_DESCRIPTION_LENGTH) {
    return `Description is too long. The limit is ${String(MAX_DESCRIPTION_LENGTH)} bytes, and accented or non-Latin characters take more than one.`
  }
  return null
}
