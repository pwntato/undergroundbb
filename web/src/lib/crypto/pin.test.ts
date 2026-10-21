// Tests for evaluatePin. Every pin is signed with a real key through the same
// pinPayload/sign the app uses, so a rejection is the evaluator's decision and
// not a malformed fixture. Each test names the rule it pins.

import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64.js'
import { SigningContext, generateSigningKey, sign, type SigningKey } from './ed25519.js'
import {
  evaluatePin,
  pinPayload,
  servedSigningKeySet,
  type PinRecord,
  type ServedUserKeys,
} from './pin.js'

const ME = 'a0000000-0000-4000-8000-000000000001'
const BOB = 'b0000000-0000-4000-8000-000000000002'
const CAROL = 'c0000000-0000-4000-8000-000000000003'

const me = generateSigningKey()
const bob = generateSigningKey()
const bobOld = generateSigningKey()
const wrapA = new Uint8Array(32).fill(7)
const wrapB = new Uint8Array(32).fill(9)
const b64 = bytesToBase64

const DAY = '2026-10-21'

function served(
  current: SigningKey,
  superseded: SigningKey[],
  wrapping = wrapA,
  keyEpoch = 0,
): ServedUserKeys {
  return {
    signingPublicKey: b64(current.publicKey),
    supersededSigningKeys: superseded.map((k) => ({ publicKey: b64(k.publicKey) })),
    wrappingPublicKey: b64(wrapping),
    keyEpoch,
  }
}

function makePin(
  opts: {
    signer?: SigningKey
    pinner?: string
    pinned?: string
    keys?: SigningKey[]
    wrapping?: Uint8Array
    recordedSigner?: SigningKey
    keyEpoch?: number
    day?: string
    recordedDay?: string
  } = {},
): PinRecord {
  const signer = opts.signer ?? me
  const keys = opts.keys ?? [bob]
  const wrapping = opts.wrapping ?? wrapA
  const payload = pinPayload(
    opts.pinner ?? ME,
    opts.pinned ?? BOB,
    signer.publicKey,
    wrapping,
    keys.map((k) => k.publicKey),
    opts.keyEpoch ?? 0,
    opts.day ?? DAY,
  )
  return {
    pinnedUserId: BOB,
    signingPublicKeys: keys.map((k) => b64(k.publicKey)),
    wrappingPublicKey: b64(wrapping),
    pinnerSigningPublicKey: b64((opts.recordedSigner ?? signer).publicKey),
    signature: b64(sign(signer, SigningContext.Pin, payload)),
    keyEpoch: opts.keyEpoch ?? 0,
    signedDay: opts.recordedDay ?? opts.day ?? DAY,
  }
}

function run(pin: PinRecord | undefined, s: ServedUserKeys) {
  return evaluatePin({
    pinnerUserId: ME,
    pinnerSigningPublicKey: me.publicKey,
    pinnedUserId: BOB,
    pin,
    served: s,
  })
}

describe('evaluatePin', () => {
  it('no pin is first-sight', () => {
    expect(run(undefined, served(bob, []))).toBe('first-sight')
  })

  it('a valid pin matching the served set is a match', () => {
    expect(run(makePin(), served(bob, []))).toBe('match')
  })

  it('order of the superseded list does not matter (set semantics)', () => {
    const pin = makePin({ keys: [bob, bobOld] })
    expect(run(pin, served(bob, [bobOld]))).toBe('match')
    expect(run(makePin({ keys: [bobOld, bob] }), served(bob, [bobOld]))).toBe('match')
  })

  // Mutation: compare only the current key -> a substituted superseded entry
  // would pass. Here the served set gains a key the pin never saw.
  it('a served set that ADDS a key is a mismatch, not an extension', () => {
    expect(run(makePin(), served(bob, [bobOld]))).toBe('mismatch')
  })

  // The pinned user's KeyEpoch is signed. Lower served = the server is
  // serving keys older than ones this account already saw: its own verdict,
  // not a plain change. Higher, or a different set at the same epoch, is a
  // change.
  it('a served epoch below the pinned one is a rollback', () => {
    expect(run(makePin({ keyEpoch: 2 }), served(bob, [], wrapA, 1))).toBe('rollback')
  })

  it('a rollback is reported even when the served keys equal the pinned ones', () => {
    expect(run(makePin({ keyEpoch: 2 }), served(bob, [], wrapA, 0))).toBe('rollback')
  })

  it('a served epoch above the pinned one is a mismatch even with the same keys', () => {
    expect(run(makePin({ keyEpoch: 1 }), served(bob, [], wrapA, 2))).toBe('mismatch')
  })

  it('an equal epoch and equal keys match', () => {
    expect(run(makePin({ keyEpoch: 2 }), served(bob, [], wrapA, 2))).toBe('match')
  })

  it('an epoch or a day changed after signing is bad-signature, not a rollback', () => {
    const pin = makePin({ keyEpoch: 2 })
    expect(run({ ...pin, keyEpoch: 1 }, served(bob, [], wrapA, 1))).toBe('bad-signature')
    expect(run({ ...pin, signedDay: '2026-10-20' }, served(bob, [], wrapA, 2))).toBe(
      'bad-signature',
    )
  })

  it.each(['yesterday', '2026-1-2', '2026-02-30', ''])(
    'a malformed signed day %j is bad-signature',
    (day) => {
      expect(run(makePin({ day, recordedDay: day }), served(bob, []))).toBe('bad-signature')
    },
  )

  it.each([-1, 1.5, Number.NaN])('an invalid epoch %j is bad-signature', (keyEpoch) => {
    expect(run({ ...makePin(), keyEpoch }, served(bob, []))).toBe('bad-signature')
  })

  it('a pin signed under the v1 pin context is bad-signature', () => {
    const payload = pinPayload(ME, BOB, me.publicKey, wrapA, [bob.publicKey], 0, DAY)
    const v1 = b64(sign(me, 'underground-bb:pin:v1' as never, payload))
    expect(run({ ...makePin(), signature: v1 }, served(bob, []))).toBe('bad-signature')
  })

  it('a swapped current key is a mismatch', () => {
    expect(run(makePin(), served(bobOld, []))).toBe('mismatch')
  })

  it('a swapped wrapping key alone is a mismatch', () => {
    expect(run(makePin(), served(bob, [], wrapB))).toBe('mismatch')
  })

  // Mutation: treat a failed verify as first-sight -> the server resets any
  // pin by flipping a byte.
  it('a corrupted signature is bad-signature, never first-sight', () => {
    const pin = makePin()
    const sig = new Uint8Array(atob(pin.signature).length)
    for (let i = 0; i < sig.length; i++) sig[i] = atob(pin.signature).charCodeAt(i)
    sig[0] = sig[0]! ^ 1
    expect(run({ ...pin, signature: b64(sig) }, served(bob, []))).toBe('bad-signature')
  })

  it('a pin rewritten by the server to match a substituted key is bad-signature', () => {
    const eve = generateSigningKey()
    const forged = { ...makePin({ signer: eve, recordedSigner: me }) }
    expect(run(forged, served(eve, []))).toBe('bad-signature')
  })

  it('a pin signed for another pinner uuid does not verify', () => {
    expect(run(makePin({ pinner: CAROL }), served(bob, []))).toBe('bad-signature')
  })

  it('a pin copied onto another pinned user does not verify', () => {
    expect(run(makePin({ pinned: CAROL }), served(bob, []))).toBe('bad-signature')
  })

  it('a pin row whose pinnedUserId is another user is bad-signature', () => {
    expect(run({ ...makePin(), pinnedUserId: CAROL }, served(bob, []))).toBe('bad-signature')
  })

  // Mutation: report a distinct verdict for a signer mismatch -> the server
  // turns any pin into "unverifiable" by rewriting one field. Both cases must
  // be bad-signature: a stranger's key with a zero signature (the forgery),
  // and a real signature under a key that is not my current one.
  it('a recorded signer that is not my current key is bad-signature', () => {
    const forged: PinRecord = {
      ...makePin(),
      pinnerSigningPublicKey: b64(bobOld.publicKey),
      signature: b64(new Uint8Array(64)),
    }
    expect(run(forged, served(bob, []))).toBe('bad-signature')
    expect(run(makePin({ signer: bobOld }), served(bob, []))).toBe('bad-signature')
  })

  it('an empty pinned key set is bad-signature', () => {
    expect(run({ ...makePin(), signingPublicKeys: [] }, served(bob, []))).toBe('bad-signature')
  })

  it('undecodable base64 never throws', () => {
    expect(run({ ...makePin(), signature: '!!!' }, served(bob, []))).toBe('bad-signature')
    expect(run(makePin(), { ...served(bob, []), wrappingPublicKey: '!!!' })).toBe('mismatch')
  })
})

describe('servedSigningKeySet', () => {
  it('returns current plus superseded, null on undecodable', () => {
    expect(servedSigningKeySet(served(bob, [bobOld]))).toHaveLength(2)
    expect(servedSigningKeySet({ ...served(bob, []), signingPublicKey: '!!!' })).toBeNull()
  })

  // Mutation: return the raw list -> a server that repeats the current key as
  // "superseded" hands the signer a duplicate that PUT /api/pins rejects.
  it('dedupes, so what a caller signs is what the server accepts', () => {
    const set = servedSigningKeySet(served(bob, [bob, bobOld, bobOld]))
    expect(set).toHaveLength(2)
    expect(set![0]).toEqual(bob.publicKey)
  })

  it('rejects a key that is not 32 bytes', () => {
    expect(servedSigningKeySet(served(bob, []))).not.toBeNull()
    expect(
      servedSigningKeySet({ ...served(bob, []), signingPublicKey: b64(new Uint8Array(31)) }),
    ).toBeNull()
  })

  it('a pin over a duplicated served list still matches', () => {
    const pin = makePin({ keys: [bob, bobOld] })
    expect(run(pin, served(bob, [bob, bobOld]))).toBe('match')
  })
})
