// AES-256-GCM via the browser's native SubtleCrypto, matching
// internal/crypto/aesgcm.go byte-for-byte (see testdata/vectors.json's
// "aead" and "aead_negative" sections).

/** Length in bytes of a GCM nonce (96 bits). */
export const NONCE_SIZE = 12

/** Length in bytes of an AES-256 key. */
export const KEY_SIZE = 32

/**
 * Thrown when a ciphertext fails authentication — wrong key, wrong AAD, or
 * tampered ciphertext. It never distinguishes which, matching Go's
 * ErrDecryptionFailed: doing so would hand an attacker an oracle.
 */
export class DecryptionFailedError extends Error {
  constructor() {
    super('crypto: decryption failed')
    this.name = 'DecryptionFailedError'
  }
}

function requireKeySize(key: Uint8Array): void {
  if (key.length !== KEY_SIZE) {
    throw new Error('crypto: key must be 32 bytes')
  }
}

function requireNonceSize(nonce: Uint8Array): void {
  if (nonce.length !== NONCE_SIZE) {
    throw new Error('crypto: nonce must be 12 bytes')
  }
}

// TypeScript's DOM lib types SubtleCrypto's BufferSource as tied to
// ArrayBuffer specifically, while Uint8Array's generic parameter widens to
// ArrayBufferLike (which also covers SharedArrayBuffer) — a type-level
// mismatch, not a real runtime hazard, since every array this module passes
// to SubtleCrypto is one we allocated ourselves or produced from hex
// decoding, never a view over a SharedArrayBuffer.
function asBufferSource(bytes: Uint8Array): BufferSource {
  return bytes as Uint8Array<ArrayBuffer>
}

/**
 * Encrypts plaintext with AES-256-GCM under key, authenticating aad
 * alongside it. Generates a fresh random 96-bit nonce from the platform
 * CSPRNG for every call — callers must never reuse a nonce with the same
 * key, and must never derive one from an item's identity rather than
 * generating it fresh.
 *
 * The returned ciphertext has the authentication tag appended, matching
 * Go's cipher.AEAD.Seal (and SubtleCrypto's own default behavior).
 */
export async function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<{ nonce: Uint8Array; ciphertext: Uint8Array }> {
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE))
  const ciphertext = await encryptWithNonce(key, nonce, plaintext, aad)
  return { nonce, ciphertext }
}

/**
 * encrypt with an explicit, caller-supplied nonce. Exists ONLY for
 * generating and verifying fixed test vectors, where a reproducible
 * ciphertext requires a fixed nonce. Every other caller MUST go through
 * encrypt, which always generates a fresh one — reusing a nonce with a real
 * key is the GCM break documented in docs/DESIGN.md.
 */
export async function encryptWithNonce(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  requireKeySize(key)
  requireNonceSize(nonce)

  const cryptoKey = await crypto.subtle.importKey('raw', asBufferSource(key), 'AES-GCM', false, [
    'encrypt',
  ])
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: asBufferSource(nonce),
      additionalData: asBufferSource(aad),
      tagLength: 128,
    },
    cryptoKey,
    asBufferSource(plaintext),
  )
  return new Uint8Array(ciphertext)
}

/**
 * Decrypts ciphertext with AES-256-GCM under key and nonce, authenticating
 * aad against it. Throws DecryptionFailedError if the key, nonce, aad, or
 * ciphertext have been altered in any way relative to what encrypt produced.
 */
export async function decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  requireKeySize(key)
  requireNonceSize(nonce)

  const cryptoKey = await crypto.subtle.importKey('raw', asBufferSource(key), 'AES-GCM', false, [
    'decrypt',
  ])
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: asBufferSource(nonce),
        additionalData: asBufferSource(aad),
        tagLength: 128,
      },
      cryptoKey,
      asBufferSource(ciphertext),
    )
    return new Uint8Array(plaintext)
  } catch {
    throw new DecryptionFailedError()
  }
}
