// A reaction's plaintext (#46), the bytes AES-GCM seals under the group key:
// ONE byte, an index into the fixed table below. Every reaction therefore seals
// to exactly 17 bytes (1 + the 16-byte GCM tag), so the ciphertext's length says
// nothing about which one it is (emoji vary from 3 to 8+ bytes in UTF-8), and
// the server refuses any other length (handlers.putReaction).
//
// THE TABLE IS THE WIRE FORMAT. It is append-only: never reorder, remove or
// reuse an index, or every stored reaction changes meaning. Index 0 is reserved
// as invalid, so a zeroed value never reads as a real reaction. A byte this
// build does not know (a newer client added one) is shown as unreadable, never
// guessed. reaction.test.ts pins every index and code point.

export const REACTION_PLAINTEXT_BYTES = 1
/** What a sealed reaction weighs: the index byte plus the GCM tag. */
export const REACTION_CIPHERTEXT_BYTES = 17

export interface ReactionKind {
  /** The byte sealed on the wire. 1 to 255; never 0. */
  readonly index: number
  readonly emoji: string
  /** For screen readers and tooltips. */
  readonly label: string
}

// Written as escapes so an editor or a formatter cannot change a code point.
export const REACTIONS: readonly ReactionKind[] = [
  { index: 1, emoji: '\u{1F44D}', label: 'Thumbs up' },
  { index: 2, emoji: '\u{2764}\u{FE0F}', label: 'Heart' },
  { index: 3, emoji: '\u{1F602}', label: 'Laughing' },
  { index: 4, emoji: '\u{1F62E}', label: 'Surprised' },
  { index: 5, emoji: '\u{1F622}', label: 'Sad' },
  { index: 6, emoji: '\u{1F389}', label: 'Celebrate' },
  { index: 7, emoji: '\u{1F621}', label: 'Angry' },
]

const BY_INDEX = new Map(REACTIONS.map((r) => [r.index, r]))

/** The reaction a byte stands for, or undefined for 0 and any byte this build does not know. */
export function reactionOf(index: number): ReactionKind | undefined {
  return BY_INDEX.get(index)
}

export function encodeReaction(index: number): Uint8Array {
  if (!BY_INDEX.has(index)) throw new Error('reaction: not a known reaction')
  return new Uint8Array([index])
}

/** Reads the index back; throws on the wrong length or a byte this build does not know. */
export function decodeReaction(bytes: Uint8Array): number {
  const index = bytes[0]
  if (bytes.length !== REACTION_PLAINTEXT_BYTES || index === undefined || !BY_INDEX.has(index)) {
    throw new Error('reaction: unknown or malformed')
  }
  return index
}
