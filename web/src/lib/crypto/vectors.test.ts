// Verifies this package against the SAME fixed vectors the Go
// implementation checks itself against (internal/crypto/testdata/vectors.json,
// #20). This is the #24 half that didn't exist yet: proving the TypeScript
// side agrees with Go's, not just with its own round-trips.
//
// Reads the vectors file directly from the Go package rather than a copy —
// there must be exactly one vectors.json in the repo, or the two
// implementations could silently drift against different "shared" files.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import { decrypt, DecryptionFailedError, encryptWithNonce } from './aesgcm.js'
import { deriveKey } from './argon2.js'
import * as ed25519 from './ed25519.js'
import { fingerprint } from './fingerprint.js'
import { bytesToHex, hexToBytes } from './hex.js'
import { signedPayload } from './payload.js'
import { unwrap, wrapWithEphemeralAndNonce } from './x25519.js'

const VECTORS_PATH = fileURLToPath(
  new URL('../../../../internal/crypto/testdata/vectors.json', import.meta.url),
)

interface VectorFile {
  version: number
  kdf: {
    password: string
    salt_hex: string
    m_kib: number
    t: number
    p: number
    key_hex: string
  }[]
  aead: {
    name: string
    key_hex: string
    nonce_hex: string
    plaintext_hex: string
    aad_hex: string
    ciphertext_hex: string
  }[]
  aead_negative: {
    name: string
    key_hex: string
    nonce_hex: string
    ciphertext_hex: string
    aad_hex: string
    wrong_aad_hex: string
  }[]
  signing: {
    name: string
    private_key_hex: string
    public_key_hex: string
    context: string
    message_hex: string
    signature_hex: string
  }[]
  signed_payload: {
    name: string
    private_key_hex: string
    public_key_hex: string
    context: string
    author_uuid: string
    group_id: string
    sort_key: string
    generation: number
    utc_day: string
    ciphertext_hex: string
    payload_hex: string
    signature_hex: string
  }[]
  wrapping: {
    name: string
    recipient_private_key_hex: string
    recipient_public_key_hex: string
    ephemeral_private_key_hex: string
    ephemeral_public_key_hex: string
    plaintext_hex: string
    aad_hex: string
    wrapped_nonce_hex: string
    wrapped_ciphertext_hex: string
  }[]
  genkey_chain: {
    name: string
    gen_n_key_hex: string
    gen_n_plus_1_key_hex: string
    aad_hex: string
    link_nonce_hex: string
    link_ciphertext_hex: string
    forward_must_fail: boolean
  }[]
  fingerprint: {
    name: string
    signing_public_key_hex: string
    wrapping_public_key_hex: string
    fingerprint: string
  }[]
}

const vectors: VectorFile = JSON.parse(readFileSync(VECTORS_PATH, 'utf8'))

describe('kdf vectors', () => {
  for (const tc of vectors.kdf) {
    it(`m=${tc.m_kib}KiB t=${tc.t} p=${tc.p}`, async () => {
      const salt = hexToBytes(tc.salt_hex)
      const want = hexToBytes(tc.key_hex)
      const got = await deriveKey(
        tc.password,
        salt,
        { memoryKiB: tc.m_kib, iterations: tc.t, parallelism: tc.p },
        want.length,
      )
      expect(bytesToHex(got)).toBe(tc.key_hex)
    })
  }
})

describe('aead vectors', () => {
  for (const tc of vectors.aead) {
    it(tc.name, async () => {
      const key = hexToBytes(tc.key_hex)
      const nonce = hexToBytes(tc.nonce_hex)
      const plaintext = hexToBytes(tc.plaintext_hex)
      const aad = hexToBytes(tc.aad_hex)

      const ciphertext = await encryptWithNonce(key, nonce, plaintext, aad)
      expect(bytesToHex(ciphertext)).toBe(tc.ciphertext_hex)

      const decrypted = await decrypt(key, nonce, ciphertext, aad)
      expect(bytesToHex(decrypted)).toBe(tc.plaintext_hex)
    })
  }
})

describe('aead negative vectors', () => {
  for (const tc of vectors.aead_negative) {
    it(tc.name, async () => {
      const key = hexToBytes(tc.key_hex)
      const nonce = hexToBytes(tc.nonce_hex)
      const ciphertext = hexToBytes(tc.ciphertext_hex)
      const wrongAad = hexToBytes(tc.wrong_aad_hex)

      await expect(decrypt(key, nonce, ciphertext, wrongAad)).rejects.toThrow(DecryptionFailedError)
    })
  }
})

describe('signing vectors', () => {
  for (const tc of vectors.signing) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      expect(bytesToHex(key.publicKey)).toBe(tc.public_key_hex)

      const message = hexToBytes(tc.message_hex)
      const signature = ed25519.sign(key, tc.context as ed25519.SigningContext, message)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)

      expect(
        ed25519.verify(key.publicKey, tc.context as ed25519.SigningContext, message, signature),
      ).toBe(true)
    })
  }
})

describe('signed payload vectors', () => {
  for (const tc of vectors.signed_payload) {
    it(tc.name, () => {
      const key = ed25519.fromGoPrivateKeyBytes(hexToBytes(tc.private_key_hex))
      const ciphertext = hexToBytes(tc.ciphertext_hex)

      const payload = signedPayload(
        tc.author_uuid,
        tc.group_id,
        tc.sort_key,
        tc.generation,
        tc.utc_day,
        ciphertext,
      )
      expect(bytesToHex(payload)).toBe(tc.payload_hex)

      const signature = ed25519.sign(key, tc.context as ed25519.SigningContext, payload)
      expect(bytesToHex(signature)).toBe(tc.signature_hex)
    })
  }
})

describe('wrapping vectors', () => {
  for (const tc of vectors.wrapping) {
    it(tc.name, async () => {
      const recipientPriv = hexToBytes(tc.recipient_private_key_hex)
      const recipientPub = hexToBytes(tc.recipient_public_key_hex)
      const ephemeralPriv = hexToBytes(tc.ephemeral_private_key_hex)
      const plaintext = hexToBytes(tc.plaintext_hex)
      const aad = hexToBytes(tc.aad_hex)
      const nonce = hexToBytes(tc.wrapped_nonce_hex)

      const wrapped = await wrapWithEphemeralAndNonce(
        recipientPub,
        ephemeralPriv,
        nonce,
        plaintext,
        aad,
      )
      expect(bytesToHex(wrapped.ephemeralPub)).toBe(tc.ephemeral_public_key_hex)
      expect(bytesToHex(wrapped.ciphertext)).toBe(tc.wrapped_ciphertext_hex)

      const unwrapped = await unwrap(recipientPriv, wrapped, aad)
      expect(bytesToHex(unwrapped)).toBe(tc.plaintext_hex)
    })
  }
})

// The negative vector issue #20 (and #24 now) calls out by name: GENKEY#<n>
// holds generation n encrypted under generation n+1's key. A holder of
// generation n+1 decrypts backward to generation n; a holder of only
// generation n has no key material that decrypts a link encrypted under
// generation n+1. This exercises the plain AES-GCM primitives, not X25519 —
// see internal/crypto/vectors_test.go's TestVectorGenkeyChain for why using
// two unrelated asymmetric keys here would test the wrong construction.
describe('genkey chain vectors', () => {
  for (const tc of vectors.genkey_chain) {
    it(tc.name, async () => {
      const genN = hexToBytes(tc.gen_n_key_hex)
      const genNPlus1 = hexToBytes(tc.gen_n_plus_1_key_hex)
      const aad = hexToBytes(tc.aad_hex)
      const nonce = hexToBytes(tc.link_nonce_hex)

      const ciphertext = await encryptWithNonce(genNPlus1, nonce, genN, aad)
      expect(bytesToHex(ciphertext)).toBe(tc.link_ciphertext_hex)

      const decrypted = await decrypt(genNPlus1, nonce, ciphertext, aad)
      expect(bytesToHex(decrypted)).toBe(tc.gen_n_key_hex)

      if (tc.forward_must_fail) {
        await expect(decrypt(genN, nonce, ciphertext, aad)).rejects.toThrow(DecryptionFailedError)
      }
    })
  }
})

describe('fingerprint vectors', () => {
  for (const tc of vectors.fingerprint) {
    it(tc.name, () => {
      const signingPub = hexToBytes(tc.signing_public_key_hex)
      const wrappingPub = hexToBytes(tc.wrapping_public_key_hex)
      expect(fingerprint(signingPub, wrappingPub)).toBe(tc.fingerprint)
    })
  }
})
