// The encrypted preferences blob (#366, docs/DESIGN.md, "The user item is mixed"): theme choice and
// custom themes, sealed under a key derived by HKDF from the X25519 PRIVATE key, so the recovery code
// (which restores the same private keys) and a password change both leave it readable, and a keypair
// change is the only thing that does not (the rotation re-seals it for exactly that reason).
//
// The server stores and serves the ciphertext and never opens it. Everything opened here is untrusted
// text: the caller parses it and runs every theme through validateCustomTheme before any of it can
// reach the page.

import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { base64ToBytes, bytesToBase64 } from './base64.js'
import { decrypt, encrypt, DecryptionFailedError, KEY_SIZE } from './aesgcm.js'
import type { LiveKeys } from './credential-material.js'

/**
 * HKDF's info for the sealing key. Distinct from the label of the key wrap (`x25519-wrap`) so the
 * same private key never yields one key for two purposes.
 */
const PREFERENCES_HKDF_INFO = 'underground-bb:preferences:v1'

/**
 * The most plaintext sealed. The server accepts 32 KiB of ciphertext (maxPreferencesCiphertextLen)
 * and AES-GCM adds a 16 byte tag; five custom themes are about 10 KB.
 */
export const MAX_PREFERENCES_BYTES = 30 * 1024

/** What a rotation seals when the old blob will not open: an empty, valid preferences document. */
export const EMPTY_PREFERENCES_TEXT = '{"v":1}'

/** A sealed blob as it crosses the wire (standard base64). */
export interface WirePreferencesBlob {
  readonly nonce: string
  readonly ciphertext: string
}

export class PreferencesTooLargeError extends Error {
  constructor() {
    super(`preferences: at most ${MAX_PREFERENCES_BYTES} bytes can be sealed`)
    this.name = 'PreferencesTooLargeError'
  }
}

/** The 32-byte sealing key for a given X25519 private key. */
export function preferencesKey(wrappingPrivateKey: Uint8Array): Uint8Array {
  return hkdf(
    sha256,
    wrappingPrivateKey,
    undefined,
    new TextEncoder().encode(PREFERENCES_HKDF_INFO),
    KEY_SIZE,
  )
}

/** Binds a blob to its owner, so another account's blob cannot be moved into this one's slot. */
export function preferencesAAD(userId: string): Uint8Array {
  return new TextEncoder().encode(`USER#${userId}:PREFERENCES`)
}

export async function sealPreferencesUnder(
  wrappingPrivateKey: Uint8Array,
  userId: string,
  text: string,
): Promise<WirePreferencesBlob> {
  const plaintext = new TextEncoder().encode(text)
  if (plaintext.length > MAX_PREFERENCES_BYTES) throw new PreferencesTooLargeError()
  const { nonce, ciphertext } = await encrypt(
    preferencesKey(wrappingPrivateKey),
    plaintext,
    preferencesAAD(userId),
  )
  return { nonce: bytesToBase64(nonce), ciphertext: bytesToBase64(ciphertext) }
}

/** The sealed text, or null if the blob does not open under this key (wrong key, wrong owner, damaged). */
export async function openPreferencesUnder(
  wrappingPrivateKey: Uint8Array,
  userId: string,
  blob: WirePreferencesBlob,
): Promise<string | null> {
  try {
    const plaintext = await decrypt(
      preferencesKey(wrappingPrivateKey),
      base64ToBytes(blob.nonce),
      base64ToBytes(blob.ciphertext),
      preferencesAAD(userId),
    )
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext)
  } catch (err) {
    if (err instanceof DecryptionFailedError || err instanceof TypeError) return null
    throw err
  }
}

export function sealPreferences(keys: LiveKeys, text: string): Promise<WirePreferencesBlob> {
  return sealPreferencesUnder(keys.wrappingKey.privateKey, keys.userId, text)
}

export function openPreferences(keys: LiveKeys, blob: WirePreferencesBlob): Promise<string | null> {
  return openPreferencesUnder(keys.wrappingKey.privateKey, keys.userId, blob)
}

/**
 * A rotation's re-seal: open the current blob with the OLD private key, seal the same text under the
 * NEW one. A blob that no longer opens (it would never open again) is replaced by an empty document
 * rather than blocking the rotation, which the server refuses to take without a blob while one exists;
 * the browser's own choice then seeds it again at the next login.
 */
export async function resealPreferences(
  keys: LiveKeys,
  newWrappingPrivateKey: Uint8Array,
  current: WirePreferencesBlob,
): Promise<WirePreferencesBlob> {
  const text = (await openPreferences(keys, current)) ?? EMPTY_PREFERENCES_TEXT
  return sealPreferencesUnder(newWrappingPrivateKey, keys.userId, text)
}
