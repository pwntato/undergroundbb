// Behavior not covered by the shared vector suite: round-tripping through
// real generated keys, and the error cases (unsupported version, malformed
// framing) that a fixed vector alone doesn't exercise.

import { describe, expect, it } from 'vitest'

import { generateSigningKey } from './ed25519.js'
import {
  decodeKeyBundle,
  encodeKeyBundle,
  KEY_BUNDLE_VERSION_1,
  MalformedKeyBundleError,
  UnsupportedKeyBundleVersionError,
  type KeyBundle,
} from './keybundle.js'
import { generateWrappingKey } from './x25519.js'

function fixedBundle(): KeyBundle {
  const signing = generateSigningKey()
  const wrapping = generateWrappingKey()
  return { signingSeed: signing.seed, wrappingPrivateKey: wrapping.privateKey }
}

describe('encodeKeyBundle / decodeKeyBundle', () => {
  it('round-trips real generated keys', () => {
    const bundle = fixedBundle()
    const encoded = encodeKeyBundle(bundle)
    const decoded = decodeKeyBundle(encoded)

    expect(decoded.signingSeed).toEqual(bundle.signingSeed)
    expect(decoded.wrappingPrivateKey).toEqual(bundle.wrappingPrivateKey)
  })

  it('starts with the version byte', () => {
    const encoded = encodeKeyBundle(fixedBundle())
    expect(encoded[0]).toBe(KEY_BUNDLE_VERSION_1)
  })

  it('rejects an unsupported version byte', () => {
    const encoded = encodeKeyBundle(fixedBundle())
    encoded[0] = KEY_BUNDLE_VERSION_1 + 1

    expect(() => decodeKeyBundle(encoded)).toThrow(UnsupportedKeyBundleVersionError)
  })

  describe('rejects malformed input', () => {
    const valid = encodeKeyBundle(fixedBundle())

    it('empty', () => {
      expect(() => decodeKeyBundle(new Uint8Array(0))).toThrow(MalformedKeyBundleError)
    })

    it('version byte only', () => {
      expect(() => decodeKeyBundle(valid.slice(0, 1))).toThrow(MalformedKeyBundleError)
    })

    it('truncated length prefix', () => {
      expect(() => decodeKeyBundle(valid.slice(0, 3))).toThrow(MalformedKeyBundleError)
    })

    it('truncated first field', () => {
      expect(() => decodeKeyBundle(valid.slice(0, 10))).toThrow(MalformedKeyBundleError)
    })

    it('length prefix claims more than present', () => {
      const tampered = valid.slice()
      tampered[4] = 0xff
      expect(() => decodeKeyBundle(tampered)).toThrow(MalformedKeyBundleError)
    })

    it('trailing garbage', () => {
      const tampered = new Uint8Array(valid.length + 1)
      tampered.set(valid, 0)
      tampered[valid.length] = 0x00
      expect(() => decodeKeyBundle(tampered)).toThrow(MalformedKeyBundleError)
    })
  })

  // Covers the guard added after review found encodeKeyBundle would happily
  // accept a signingSeed of the wrong size -- e.g. Go's own 64-byte
  // ed25519.PrivateKey encoding (seed||pubkey), which ed25519.ts's
  // SigningKey doc comment specifically names as what "cross[es] the wire"
  // elsewhere in this codebase, making it a plausible mistake for whatever
  // signup code eventually calls this. Before this guard, that value would
  // wrap and register successfully and then fail every subsequent login,
  // undetectably, since the server never sees this plaintext to catch the
  // mismatch.
  describe('rejects wrong-size fields', () => {
    const valid = fixedBundle()

    it('64-byte Go-style signing key instead of the 32-byte seed', () => {
      const oversized = new Uint8Array(64)
      oversized.set(valid.signingSeed, 0)
      oversized.set(valid.signingSeed, 32)
      expect(() =>
        encodeKeyBundle({ signingSeed: oversized, wrappingPrivateKey: valid.wrappingPrivateKey }),
      ).toThrow(MalformedKeyBundleError)
    })

    it('empty signing seed', () => {
      expect(() =>
        encodeKeyBundle({
          signingSeed: new Uint8Array(0),
          wrappingPrivateKey: valid.wrappingPrivateKey,
        }),
      ).toThrow(MalformedKeyBundleError)
    })

    it('short wrapping key', () => {
      expect(() =>
        encodeKeyBundle({
          signingSeed: valid.signingSeed,
          wrappingPrivateKey: valid.wrappingPrivateKey.slice(0, 16),
        }),
      ).toThrow(MalformedKeyBundleError)
    })

    it('empty wrapping key', () => {
      expect(() =>
        encodeKeyBundle({ signingSeed: valid.signingSeed, wrappingPrivateKey: new Uint8Array(0) }),
      ).toThrow(MalformedKeyBundleError)
    })
  })

  // Documents parity with Go's fix for the aliasing bug review found there:
  // decodeKeyBundle must return copies, not views over the input buffer, so
  // zeroing the input after decoding -- the ordinary thing to do with an
  // unwrapped plaintext once its keys are extracted -- cannot silently zero
  // the decoded KeyBundle too. TS's Uint8Array.slice() already copies, so
  // this was true before the Go-side fix; this test makes that guarantee
  // explicit and durable rather than incidental.
  it('returns independent copies, not views over the input buffer', () => {
    const bundle = fixedBundle()
    const encoded = encodeKeyBundle(bundle)
    const decoded = decodeKeyBundle(encoded)

    encoded.fill(0)

    expect(decoded.signingSeed).toEqual(bundle.signingSeed)
    expect(decoded.wrappingPrivateKey).toEqual(bundle.wrappingPrivateKey)
  })
})
