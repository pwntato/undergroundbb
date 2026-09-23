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
})
