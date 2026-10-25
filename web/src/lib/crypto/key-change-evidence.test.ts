import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64'
import { generateSigningKey } from './ed25519'
import { keyChangeEvidence } from './key-change-evidence'
import { makeKeyChange } from './own-history.testkit'

const USER = 'b0000000-0000-4000-8000-000000000002'
const k0 = generateSigningKey()
const k1 = generateSigningKey()
const k2 = generateSigningKey()
const b64 = bytesToBase64
const pinOf = (key: { publicKey: Uint8Array }, keyEpoch: number) => ({
  signingPublicKeys: [b64(key.publicKey)],
  keyEpoch,
})
const servedOf = (key: { publicKey: Uint8Array }) => ({ signingPublicKey: b64(key.publicKey) })
const link = (from: typeof k0, to: typeof k0, epoch: number) =>
  makeKeyChange({ userId: USER, from, to, epoch, day: '2026-10-01' }).change

describe('keyChangeEvidence', () => {
  it('is a signed rotation when the chain runs from the pinned key to the served one', () => {
    expect(
      keyChangeEvidence({
        userId: USER,
        pin: pinOf(k0, 0),
        served: servedOf(k1),
        changes: [link(k0, k1, 1)],
      }),
    ).toBe('signed-rotation')
  })

  it('follows a chain of several rotations from the pinned epoch', () => {
    expect(
      keyChangeEvidence({
        userId: USER,
        pin: pinOf(k1, 1),
        served: servedOf(k2),
        changes: [link(k0, k1, 1), link(k1, k2, 2)],
      }),
    ).toBe('signed-rotation')
  })

  it('does not depend on the order of the pinned keys', () => {
    const pin = { signingPublicKeys: [b64(k2.publicKey), b64(k1.publicKey)], keyEpoch: 1 }
    expect(
      keyChangeEvidence({
        userId: USER,
        pin,
        served: servedOf(k2),
        changes: [link(k0, k1, 1), link(k1, k2, 2)],
      }),
    ).toBe('signed-rotation')
  })

  it('has no link when the keys changed without a signature from the saved ones', () => {
    // The saved key is k0 but the chain only ever left k1.
    expect(
      keyChangeEvidence({
        userId: USER,
        pin: pinOf(k0, 0),
        served: servedOf(k2),
        changes: [link(k1, k2, 1)],
      }),
    ).toBe('no-link')
    expect(
      keyChangeEvidence({ userId: USER, pin: pinOf(k0, 0), served: servedOf(k0), changes: [] }),
    ).toBe('no-link')
  })

  it('is unverified when the chain does not verify or does not end at the served key', () => {
    const tampered = { ...link(k0, k1, 1), newSignature: b64(new Uint8Array(64).fill(1)) }
    expect(
      keyChangeEvidence({
        userId: USER,
        pin: pinOf(k0, 0),
        served: servedOf(k1),
        changes: [tampered],
      }),
    ).toBe('unverified')
    expect(
      keyChangeEvidence({
        userId: USER,
        pin: pinOf(k0, 0),
        served: servedOf(k2),
        changes: [link(k0, k1, 1)],
      }),
    ).toBe('unverified')
    // A link signed for someone else is not theirs.
    expect(
      keyChangeEvidence({
        userId: 'c0000000-0000-4000-8000-000000000003',
        pin: pinOf(k0, 0),
        served: servedOf(k1),
        changes: [link(k0, k1, 1)],
      }),
    ).toBe('unverified')
  })

  it('does not throw on a malformed key', () => {
    expect(
      keyChangeEvidence({
        userId: USER,
        pin: { signingPublicKeys: ['!!'], keyEpoch: 0 },
        served: servedOf(k1),
        changes: [link(k0, k1, 1)],
      }),
    ).toBe('unverified')
  })
})
