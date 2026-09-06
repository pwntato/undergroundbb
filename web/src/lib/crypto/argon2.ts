// Argon2id key derivation via hash-wasm, matching Go's
// golang.org/x/crypto/argon2.IDKey byte-for-byte (see
// testdata/vectors.json's "kdf" section).
//
// This is the ONLY primitive in this package with no Go production
// counterpart — Argon2id runs exclusively in the browser per
// docs/DESIGN.md, so the Go side only implements it inside
// testdata/gen/main.go as a test-vector oracle. Both must agree because the
// server stores the parameters this module reads (docs/DESIGN.md: "the
// parameters read from the stored attributes rather than from client
// constants"), and the vector proves the read path, not just the numbers.

import { argon2id } from 'hash-wasm'
import { hexToBytes } from './hex.js'

/**
 * The Argon2id parameters this project stores for new users, per
 * docs/DESIGN.md: "The Argon2id parameters are m=64 MiB, t=3, p=1, and they
 * are stored on the item rather than compiled into the client." This
 * constant is the default for NEW derivations only — deriveKey always takes
 * its parameters as arguments, read from the stored PROFILE item, because a
 * silently-changed compiled-in default would lock out every existing user
 * on their next login. Naming the numbers matters: Argon2id without them is
 * not a security claim.
 */
export const DEFAULT_PARAMS = {
  memoryKiB: 64 * 1024,
  iterations: 3,
  parallelism: 1,
} as const

export interface Argon2idParams {
  readonly memoryKiB: number
  readonly iterations: number
  readonly parallelism: number
}

/**
 * Derives a key from password and salt with Argon2id, per the
 * caller-supplied parameters — always read from the server-stored PROFILE
 * item, never from DEFAULT_PARAMS directly, so a user who registered under
 * older parameters still derives the same key their private-key blob was
 * wrapped under.
 *
 * outputLength defaults to 32 (crypto.KEY_SIZE), the AES-256-GCM key used
 * to unwrap the stored private keys.
 */
export async function deriveKey(
  password: string,
  salt: Uint8Array,
  params: Argon2idParams,
  outputLength = 32,
): Promise<Uint8Array> {
  const hex = await argon2id({
    password,
    salt,
    parallelism: params.parallelism,
    iterations: params.iterations,
    memorySize: params.memoryKiB,
    hashLength: outputLength,
    outputType: 'hex',
  })
  return hexToBytes(hex)
}
