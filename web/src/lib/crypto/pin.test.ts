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

function served(current: SigningKey, superseded: SigningKey[], wrapping = wrapA): ServedUserKeys {
  return {
    signingPublicKey: b64(current.publicKey),
    supersededSigningKeys: superseded.map((k) => ({ publicKey: b64(k.publicKey) })),
    wrappingPublicKey: b64(wrapping),
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
  )
  return {
    pinnedUserId: BOB,
    signingPublicKeys: keys.map((k) => b64(k.publicKey)),
    wrappingPublicKey: b64(wrapping),
    pinnerSigningPublicKey: b64((opts.recordedSigner ?? signer).publicKey),
    signature: b64(sign(signer, SigningContext.Pin, payload)),
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

  it('a pin signed under a different key than my current one is stale-signer', () => {
    expect(run(makePin({ signer: bobOld }), served(bob, []))).toBe('stale-signer')
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
})
