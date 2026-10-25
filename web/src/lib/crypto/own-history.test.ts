// Tests for the caller's verified key history. Every link is signed by real
// keys over the payload the app builds, so a rejection is the verifier's
// decision and not a malformed fixture. Each test names the rule it pins.

import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64.js'
import { generateSigningKey, sign, SigningContext } from './ed25519.js'
import { evaluatePin, pinPayload, type PinRecord } from './pin.js'
import {
  evaluateVerification,
  verificationPayload,
  type VerificationRecord,
} from './verification.js'
import {
  buildOwnKeyHistory,
  ownKeyHistoryForVerifiers,
  ownKeys,
  ownSignerAccepted,
} from './own-history.js'
import { keysOnDay } from './grant-chain.js'
import { makeKeyChange, rowId } from './own-history.testkit.js'

const ME = 'a0000000-0000-4000-8000-000000000001'
const BOB = 'b0000000-0000-4000-8000-000000000002'
const b64 = bytesToBase64
const wrap = new Uint8Array(32).fill(7)

const k0 = generateSigningKey()
const k1 = generateSigningKey()
const k2 = generateSigningKey()
const bobKey = generateSigningKey()

function pinBy(signer: typeof k0, day: string): { pin: PinRecord; id: Uint8Array } {
  const payload = pinPayload(ME, BOB, signer.publicKey, wrap, [bobKey.publicKey], 0, day)
  const signature = sign(signer, SigningContext.Pin, payload)
  return {
    pin: {
      pinnedUserId: BOB,
      signingPublicKeys: [b64(bobKey.publicKey)],
      wrappingPublicKey: b64(wrap),
      pinnerSigningPublicKey: b64(signer.publicKey),
      signature: b64(signature),
      keyEpoch: 0,
      signedDay: day,
    },
    id: rowId(`PIN#${BOB}`, signature),
  }
}

const served = {
  signingPublicKey: b64(bobKey.publicKey),
  supersededSigningKeys: [],
  wrappingPublicKey: b64(wrap),
  keyEpoch: 0,
}

describe('buildOwnKeyHistory', () => {
  it('is an empty history for an account that never rotated', () => {
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k0.publicKey,
      changes: [],
      rosters: [],
    })
    expect(h).not.toBeNull()
    expect(ownKeys(h!)).toHaveLength(1)
  })

  it('accepts a two-link chain that ends at the key the caller holds', () => {
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    const b = makeKeyChange({ userId: ME, from: k1, to: k2, epoch: 2, day: '2026-10-10' })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k2.publicKey,
      changes: [b.change, a.change],
      rosters: [a.roster, b.roster],
    })
    expect(h?.links.map((l) => l.epoch)).toEqual([1, 2])
    expect(ownKeys(h!)).toHaveLength(3)
  })

  it('rejects a chain that does not end at the key the caller holds (a fork)', () => {
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    expect(
      buildOwnKeyHistory({
        userId: ME,
        ownSigningKey: k2.publicKey,
        changes: [a.change],
        rosters: [],
      }),
    ).toBeNull()
  })

  it('rejects a link whose new-key signature does not verify', () => {
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    const forged = { ...a.change, newSignature: a.change.oldSignature }
    expect(
      buildOwnKeyHistory({
        userId: ME,
        ownSigningKey: k1.publicKey,
        changes: [forged],
        rosters: [],
      }),
    ).toBeNull()
  })

  it('rejects a link whose old-key signature does not verify', () => {
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    const forged = { ...a.change, oldSignature: a.change.newSignature }
    expect(
      buildOwnKeyHistory({
        userId: ME,
        ownSigningKey: k1.publicKey,
        changes: [forged],
        rosters: [],
      }),
    ).toBeNull()
  })

  it('rejects a chain signed for another user', () => {
    const a = makeKeyChange({ userId: BOB, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    expect(
      buildOwnKeyHistory({
        userId: ME,
        ownSigningKey: k1.publicKey,
        changes: [a.change],
        rosters: [],
      }),
    ).toBeNull()
  })

  it('rejects a chain with a hidden link (epochs must run 1..n)', () => {
    const b = makeKeyChange({ userId: ME, from: k1, to: k2, epoch: 2, day: '2026-10-10' })
    expect(
      buildOwnKeyHistory({
        userId: ME,
        ownSigningKey: k2.publicKey,
        changes: [b.change],
        rosters: [],
      }),
    ).toBeNull()
  })

  it("rejects a link whose old key is not the previous link's new key", () => {
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    const b = makeKeyChange({ userId: ME, from: k0, to: k2, epoch: 2, day: '2026-10-10' })
    expect(
      buildOwnKeyHistory({
        userId: ME,
        ownSigningKey: k2.publicKey,
        changes: [a.change, b.change],
        rosters: [],
      }),
    ).toBeNull()
  })

  it('rejects links dated out of order', () => {
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-10' })
    const b = makeKeyChange({ userId: ME, from: k1, to: k2, epoch: 2, day: '2026-10-01' })
    expect(
      buildOwnKeyHistory({
        userId: ME,
        ownSigningKey: k2.publicKey,
        changes: [a.change, b.change],
        rosters: [],
      }),
    ).toBeNull()
  })

  it('keeps the chain but drops a roster whose entries do not match the signed digest', () => {
    const { pin, id } = pinBy(k0, '2026-09-20')
    void pin
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: '2026-10-01',
      listed: [id],
      served: [],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })
    expect(h?.links[0]?.roster).toBeNull()
  })
})

describe('evaluatePin with a superseded signer', () => {
  function history(listPin: boolean, rotationDay = '2026-10-01') {
    const { pin, id } = pinBy(k0, '2026-09-20')
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: rotationDay,
      listed: listPin ? [id] : [],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    return { pin, h }
  }
  const base = { pinnerUserId: ME, pinnerSigningPublicKey: k1.publicKey, pinnedUserId: BOB, served }

  it('is bad-signature without the history (current key only)', () => {
    const { pin } = history(true)
    expect(evaluatePin({ ...base, pin })).toBe('bad-signature')
  })

  it('matches when the old key signed it, inside its interval, and the rotation listed it', () => {
    const { pin, h } = history(true)
    expect(evaluatePin({ ...base, pin, pinnerHistory: h })).toBe('match')
  })

  it('is bad-signature when the rotation did not list the row', () => {
    const { pin, h } = history(false)
    expect(evaluatePin({ ...base, pin, pinnerHistory: h })).toBe('bad-signature')
  })

  it('is bad-signature when the day is after the rotation (a leaked old key backdating forward)', () => {
    const { pin, id } = pinBy(k0, '2026-10-05')
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: '2026-10-01',
      listed: [id],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    expect(evaluatePin({ ...base, pin, pinnerHistory: h })).toBe('bad-signature')
  })

  it('accepts the rotation day itself', () => {
    const { pin, id } = pinBy(k0, '2026-10-01')
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: '2026-10-01',
      listed: [id],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    expect(evaluatePin({ ...base, pin, pinnerHistory: h })).toBe('match')
  })

  it('is bad-signature when the day is before the key was introduced', () => {
    const { pin, id } = pinBy(k1, '2026-09-25')
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    const b = makeKeyChange({
      userId: ME,
      from: k1,
      to: k2,
      epoch: 2,
      day: '2026-10-10',
      listed: [id],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k2.publicKey,
      changes: [a.change, b.change],
      rosters: [a.roster, b.roster],
    })!
    expect(
      evaluatePin({ ...base, pinnerSigningPublicKey: k2.publicKey, pin, pinnerHistory: h }),
    ).toBe('bad-signature')
  })

  it('is bad-signature when the listed entry is for another row (a signature relabelled to another pin)', () => {
    const { pin } = pinBy(k0, '2026-09-20')
    const other = pinBy(k0, '2026-09-21')
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: '2026-10-01',
      listed: [other.id],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    expect(evaluatePin({ ...base, pin, pinnerHistory: h })).toBe('bad-signature')
  })

  it('is bad-signature when the signer is a key the history never held', () => {
    const stranger = generateSigningKey()
    const { pin, id } = pinBy(stranger, '2026-09-20')
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: '2026-10-01',
      listed: [id],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    expect(evaluatePin({ ...base, pin, pinnerHistory: h })).toBe('bad-signature')
  })

  it('still verifies the signature itself (a listed row with a bad signature)', () => {
    const { pin, h } = history(true)
    const broken = { ...pin, signingPublicKeys: [b64(generateSigningKey().publicKey)] }
    expect(evaluatePin({ ...base, pin: broken, pinnerHistory: h })).toBe('bad-signature')
  })

  it("ignores a history whose current key is not the caller's", () => {
    const { pin, h } = history(true)
    expect(
      evaluatePin({ ...base, pinnerSigningPublicKey: k2.publicKey, pin, pinnerHistory: h }),
    ).toBe('bad-signature')
  })
})

describe('evaluateVerification with a superseded signer', () => {
  function record(day: string) {
    const payload = verificationPayload(ME, BOB, k0.publicKey, 'fp', day)
    const signature = sign(k0, SigningContext.Verification, payload)
    const rec: VerificationRecord = {
      verifiedUserId: BOB,
      fingerprint: 'fp',
      verifierSigningPublicKey: b64(k0.publicKey),
      signature: b64(signature),
      signedDay: day,
    }
    return { rec, id: rowId(`VERIFIED#${BOB}`, signature) }
  }
  const base = {
    verifierUserId: ME,
    verifierSigningPublicKey: k1.publicKey,
    verifiedUserId: BOB,
    servedFingerprint: 'fp',
  }

  it('is verified when the old key signed it inside its interval and the rotation listed it', () => {
    const { rec, id } = record('2026-09-20')
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: '2026-10-01',
      listed: [id],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    expect(evaluateVerification({ ...base, record: rec, verifierHistory: h })).toBe('verified')
    expect(evaluateVerification({ ...base, record: rec })).toBe('bad-signature')
  })

  it('is bad-signature when the rotation did not list it', () => {
    const { rec } = record('2026-09-20')
    const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    expect(evaluateVerification({ ...base, record: rec, verifierHistory: h })).toBe('bad-signature')
  })

  it('is bad-signature when the day is after the rotation', () => {
    const { rec, id } = record('2026-10-05')
    const a = makeKeyChange({
      userId: ME,
      from: k0,
      to: k1,
      epoch: 1,
      day: '2026-10-01',
      listed: [id],
    })
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k1.publicKey,
      changes: [a.change],
      rosters: [a.roster],
    })!
    expect(evaluateVerification({ ...base, record: rec, verifierHistory: h })).toBe('bad-signature')
  })
})

describe('ownSignerAccepted', () => {
  it('always accepts the current key, with or without a listing', () => {
    const h = buildOwnKeyHistory({
      userId: ME,
      ownSigningKey: k0.publicKey,
      changes: [],
      rosters: [],
    })!
    expect(ownSignerAccepted(h, k0.publicKey, '2026-10-01', `PIN#${BOB}`, new Uint8Array(64))).toBe(
      true,
    )
  })
})

describe('ownKeyHistoryForVerifiers', () => {
  const day = (d: string) => Date.parse(`${d}T00:00:00Z`)
  const a = makeKeyChange({ userId: ME, from: k0, to: k1, epoch: 1, day: '2026-10-01' })
  const b = makeKeyChange({ userId: ME, from: k1, to: k2, epoch: 2, day: '2026-10-10' })
  const h = buildOwnKeyHistory({
    userId: ME,
    ownSigningKey: k2.publicKey,
    changes: [a.change, b.change],
    rosters: [],
  })!
  const keyIdsOn = (d: string) =>
    keysOnDay(ownKeyHistoryForVerifiers(h), day(d)).map((k) =>
      [k0, k1, k2].findIndex((x) => b64(x.publicKey) === b64(k)),
    )

  it('puts each key on the days of its signed interval and the current key after', () => {
    expect(keyIdsOn('2026-01-01')).toEqual([0])
    expect(keyIdsOn('2026-10-05')).toEqual([1])
    expect(keyIdsOn('2026-12-01')).toEqual([2])
  })

  it('has both keys on a rotation day', () => {
    expect(keyIdsOn('2026-10-01').sort()).toEqual([0, 1])
    expect(keyIdsOn('2026-10-10').sort()).toEqual([1, 2])
  })
})
