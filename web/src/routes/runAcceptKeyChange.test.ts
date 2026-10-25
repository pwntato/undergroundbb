import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { UserDetail } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { generateSigningKey, sign, SigningContext } from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { makeKeyChange } from '@/lib/crypto/own-history.testkit'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import {
  acceptFailureMessage,
  evidenceText,
  prepareAcceptKeyChange,
  runAcceptKeyChange,
  type AcceptKeyChangeDeps,
} from './runAcceptKeyChange'

const ME = 'a0000000-0000-4000-8000-000000000001'
const X = 'b0000000-0000-4000-8000-000000000002'
const b64 = bytesToBase64
const me = generateSigningKey()
const k0 = generateSigningKey()
const k1 = generateSigningKey()
// The testkit's rotation lists these wrapping keys.
const WRAP_OLD = new Uint8Array(32).fill(3)
const WRAP_NEW = new Uint8Array(32).fill(4)

function pinOf(
  key: { publicKey: Uint8Array },
  wrapping: Uint8Array,
  keyEpoch: number,
  signer = me,
): PinRecord {
  const payload = pinPayload(ME, X, me.publicKey, wrapping, [key.publicKey], keyEpoch, '2026-10-01')
  return {
    pinnedUserId: X,
    signingPublicKeys: [b64(key.publicKey)],
    wrappingPublicKey: b64(wrapping),
    pinnerSigningPublicKey: b64(me.publicKey),
    signature: b64(sign(signer, SigningContext.Pin, payload)),
    keyEpoch,
    signedDay: '2026-10-01',
  }
}

const printOfServed = () => fingerprint(k1.publicKey, WRAP_NEW)

function served(over: Partial<UserDetail> = {}): UserDetail {
  return {
    userId: X,
    username: 'x',
    signingPublicKey: b64(k1.publicKey),
    wrappingPublicKey: b64(WRAP_NEW),
    supersededSigningKeys: [
      { publicKey: b64(k0.publicKey), from: '2026-01-01', until: '2026-10-02' },
    ],
    keyEpoch: 1,
    keyChanges: [
      makeKeyChange({ userId: X, from: k0, to: k1, epoch: 1, day: '2026-10-02' }).change,
    ],
    ...over,
  } as UserDetail
}

function setup(
  o: {
    pin?: PinRecord | null
    served?: UserDetail
    getError?: Error
    pinError?: Error
  } = {},
) {
  const pinned: Parameters<AcceptKeyChangeDeps['pinKeys']>[] = []
  const deps: AcceptKeyChangeDeps = {
    selfUserId: ME,
    getUserDetail: vi.fn(async () => {
      if (o.getError) throw o.getError
      return o.served ?? served()
    }),
    ownSigningKey: async () => b64(me.publicKey),
    listPins: async () => (o.pin === null ? [] : [o.pin ?? pinOf(k0, WRAP_OLD, 0)]),
    pinKeys: async (...args) => {
      if (o.pinError) throw o.pinError
      pinned.push(args)
    },
  }
  return { deps, pinned }
}

describe('accepting a key change', () => {
  it('offers a changed member with the evidence and the fingerprint, and writes nothing yet', async () => {
    const { deps, pinned } = setup()
    expect(await prepareAcceptKeyChange(deps, X)).toEqual({
      ok: true,
      fingerprint: printOfServed(),
      evidence: 'signed-rotation',
    })
    expect(pinned).toEqual([])
  })

  it('replaces the pin with the keys served now once the fingerprint is confirmed', async () => {
    const { deps, pinned } = setup()
    expect(await runAcceptKeyChange(deps, X, printOfServed())).toEqual({ ok: true })
    expect(pinned).toEqual([[X, [b64(k1.publicKey), b64(k0.publicKey)], b64(WRAP_NEW), 1]])
  })

  it('says when nothing links the saved keys to the served ones', async () => {
    const { deps } = setup({ served: served({ keyChanges: [] }) })
    expect(await prepareAcceptKeyChange(deps, X)).toMatchObject({ ok: true, evidence: 'no-link' })
    const bad = served()
    const tampered = [{ ...bad.keyChanges[0]!, newSignature: b64(new Uint8Array(64).fill(1)) }]
    const t = setup({ served: served({ keyChanges: tampered }) })
    expect(await prepareAcceptKeyChange(t.deps, X)).toMatchObject({
      ok: true,
      evidence: 'unverified',
    })
  })

  it('does not accept a rollback, whatever the fingerprint', async () => {
    // Saved at epoch 2; the server now serves epoch 1.
    const { deps, pinned } = setup({ pin: pinOf(k0, WRAP_OLD, 2) })
    expect(await prepareAcceptKeyChange(deps, X)).toEqual({ ok: false, kind: 'rollback' })
    expect(await runAcceptKeyChange(deps, X, printOfServed())).toEqual({
      ok: false,
      kind: 'rollback',
    })
    expect(pinned).toEqual([])
  })

  it('does not treat a pin that does not verify as a key change', async () => {
    const { deps, pinned } = setup({ pin: pinOf(k0, WRAP_OLD, 0, generateSigningKey()) })
    expect(await runAcceptKeyChange(deps, X, printOfServed())).toEqual({
      ok: false,
      kind: 'pinUnverifiable',
    })
    expect(pinned).toEqual([])
  })

  it('reports a failed read of your own key history, not tampering, when a pin does not verify', async () => {
    const forged = pinOf(k0, WRAP_OLD, 0, generateSigningKey())
    const { deps } = setup({ pin: forged })
    const failing: AcceptKeyChangeDeps = { ...deps, ownKeyHistoryFailure: async () => 'offline' }
    expect(await prepareAcceptKeyChange(failing, X)).toEqual({
      ok: false,
      kind: 'unchecked',
      reason: 'could not load your key history: offline',
    })
    // The history loaded and the pin still does not verify: that is tampering.
    const loaded: AcceptKeyChangeDeps = { ...deps, ownKeyHistoryFailure: async () => null }
    expect(await prepareAcceptKeyChange(loaded, X)).toEqual({ ok: false, kind: 'pinUnverifiable' })
  })

  it('has nothing to accept when the keys match the pin or there is no pin', async () => {
    const same = setup({
      pin: pinOf(k1, WRAP_NEW, 1),
      served: served({ supersededSigningKeys: [] }),
    })
    expect(await prepareAcceptKeyChange(same.deps, X)).toEqual({ ok: false, kind: 'notChanged' })
    const none = setup({ pin: null })
    expect(await runAcceptKeyChange(none.deps, X, printOfServed())).toEqual({
      ok: false,
      kind: 'notChanged',
    })
    expect(same.pinned).toEqual([])
    expect(none.pinned).toEqual([])
  })

  it('writes nothing when the keys served now are not the ones whose fingerprint was confirmed', async () => {
    const { deps, pinned } = setup()
    const other = fingerprint(generateSigningKey().publicKey, WRAP_NEW)
    for (const confirmed of [other, '']) {
      expect(await runAcceptKeyChange(deps, X, confirmed)).toEqual({
        ok: false,
        kind: 'keysChanged',
      })
    }
    expect(pinned).toEqual([])
  })

  it('maps what can go wrong reading and writing', async () => {
    const cases: [ReturnType<typeof setup>, string][] = [
      [setup({ getError: new ApiError(404, 'no') }), 'notFound'],
      [setup({ getError: new ApiError(401, 'no') }), 'authRequired'],
      [setup({ getError: new Error('offline') }), 'unchecked'],
      [setup({ served: served({ deleted: true }) }), 'deleted'],
      [setup({ pinError: new ApiError(409, 'again', 'pin_epoch_stale') }), 'stale'],
      [setup({ pinError: new Error('crypto: no live keys cached') }), 'coldKeys'],
      [setup({ pinError: new Error('503') }), 'unchecked'],
    ]
    for (const [{ deps }, kind] of cases) {
      expect(await runAcceptKeyChange(deps, X, printOfServed())).toMatchObject({ ok: false, kind })
    }
  })

  it('refuses to accept the caller', async () => {
    const { deps } = setup()
    expect(await prepareAcceptKeyChange(deps, ME)).toMatchObject({ ok: false, kind: 'rejected' })
  })

  it('has words for every outcome', () => {
    const kinds = [
      'notChanged',
      'rollback',
      'pinUnverifiable',
      'keysChanged',
      'stale',
      'authRequired',
      'notFound',
      'deleted',
      'coldKeys',
    ] as const
    for (const kind of kinds) expect(acceptFailureMessage({ ok: false, kind })).toMatch(/\S/)
    expect(acceptFailureMessage({ ok: false, kind: 'unchecked', reason: 'boom' })).toContain('boom')
    for (const e of ['signed-rotation', 'no-link', 'unverified'] as const) {
      expect(evidenceText(e)).toMatch(/\S/)
    }
    expect(evidenceText('no-link')).toContain('Only accept if')
  })
})
