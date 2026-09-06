// Behavior not covered by the shared vector suite: unwrap's guard against a
// malformed ephemeral public key. Go's Unwrap rejects this explicitly with
// ErrInvalidPublicKey before ECDH; this proves the TS port does too, rather
// than just trusting @noble/curves to throw something.

import { describe, expect, it } from 'vitest'

import { generateWrappingKey, InvalidPublicKeyError, unwrap, wrap } from './x25519.js'

describe('unwrap', () => {
  it('rejects an ephemeralPub of the wrong length before deriving anything', async () => {
    const recipient = generateWrappingKey()
    const aad = new Uint8Array([1, 2, 3])
    const wrapped = await wrap(recipient.publicKey, new Uint8Array(32).fill(7), aad)

    const tampered = { ...wrapped, ephemeralPub: wrapped.ephemeralPub.slice(0, 31) }

    await expect(unwrap(recipient.privateKey, tampered, aad)).rejects.toThrow(InvalidPublicKeyError)
  })

  it('still unwraps correctly when ephemeralPub has the right length', async () => {
    const recipient = generateWrappingKey()
    const aad = new Uint8Array([1, 2, 3])
    const plaintext = new Uint8Array(32).fill(7)
    const wrapped = await wrap(recipient.publicKey, plaintext, aad)

    await expect(unwrap(recipient.privateKey, wrapped, aad)).resolves.toEqual(plaintext)
  })
})
