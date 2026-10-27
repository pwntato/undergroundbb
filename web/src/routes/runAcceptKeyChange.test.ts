import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { UserDetail } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { generateSigningKey, sign, SigningContext } from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { makeKeyChange } from '@/lib/crypto/own-history.testkit'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import { wrapRecordPayload } from '@/lib/crypto/group'
import type { MemberEntry } from '@/lib/api/groups'
import {
  acceptFailureMessage,
  evidenceText,
  prepareAcceptKeyChange,
  runAcceptKeyChange,
  wrapEvidenceText,
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

const GROUP = 'd0000000-0000-4000-8000-000000000004'
const ADMIN = 'e0000000-0000-4000-8000-000000000005'
const adminKey = generateSigningKey()
const ENTRY: MemberEntry = { userId: X, role: 'member', generation: 3, wrapEpoch: 1 }
const CTX = { groupId: GROUP, entry: ENTRY }

function recordBy(wrapper: string, key: typeof k0, reason: 'self' | 'approval') {
  const day = '2026-10-20'
  const payload = wrapRecordPayload(GROUP, wrapper, X, 3, 1, reason, day)
  return {
    wrapperUserId: wrapper,
    reason,
    day,
    signature: b64(sign(key, SigningContext.WrapRecord, payload)),
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
    expect(await prepareAcceptKeyChange(deps, X, CTX)).toEqual({
      ok: true,
      fingerprint: printOfServed(),
      evidence: 'signed-rotation',
      wrap: { kind: 'none' },
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
    expect(await prepareAcceptKeyChange(deps, X, CTX)).toMatchObject({
      ok: true,
      evidence: 'no-link',
    })
    const bad = served()
    const tampered = [{ ...bad.keyChanges[0]!, newSignature: b64(new Uint8Array(64).fill(1)) }]
    const t = setup({ served: served({ keyChanges: tampered }) })
    expect(await prepareAcceptKeyChange(t.deps, X, CTX)).toMatchObject({
      ok: true,
      evidence: 'unverified',
    })
  })

  it('does not accept a rollback, whatever the fingerprint', async () => {
    // Saved at epoch 2; the server now serves epoch 1.
    const { deps, pinned } = setup({ pin: pinOf(k0, WRAP_OLD, 2) })
    expect(await prepareAcceptKeyChange(deps, X, CTX)).toEqual({ ok: false, kind: 'rollback' })
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
    expect(await prepareAcceptKeyChange(failing, X, CTX)).toEqual({
      ok: false,
      kind: 'unchecked',
      reason: 'could not load your key history: offline',
    })
    // The history loaded and the pin still does not verify: that is tampering.
    const loaded: AcceptKeyChangeDeps = { ...deps, ownKeyHistoryFailure: async () => null }
    expect(await prepareAcceptKeyChange(loaded, X, CTX)).toEqual({
      ok: false,
      kind: 'pinUnverifiable',
    })
  })

  it('has nothing to accept when the keys match the pin or there is no pin', async () => {
    const same = setup({
      pin: pinOf(k1, WRAP_NEW, 1),
      served: served({ supersededSigningKeys: [] }),
    })
    expect(await prepareAcceptKeyChange(same.deps, X, CTX)).toEqual({
      ok: false,
      kind: 'notChanged',
    })
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
    expect(await prepareAcceptKeyChange(deps, ME, CTX)).toMatchObject({
      ok: false,
      kind: 'rejected',
    })
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

describe('wrapEvidenceText', () => {
  const label = (id: string) => `<${id}>`
  it('words each outcome distinctly, and never calls an unreadable record "no record"', () => {
    const texts = [
      wrapEvidenceText({ kind: 'approved', wrapperUserId: ADMIN }, label),
      wrapEvidenceText({ kind: 'self' }, label),
      wrapEvidenceText({ kind: 'none' }, label),
      wrapEvidenceText({ kind: 'invalid' }, label),
      wrapEvidenceText({ kind: 'unchecked', reason: 'x' }, label),
    ]
    expect(new Set(texts).size).toBe(5)
    expect(texts[0]).toContain(`<${ADMIN}>`)
    expect(texts[4]).toMatch(/could not check/i)
    expect(texts[4]).not.toMatch(/no signed record/i)
  })
})

describe('who wrapped their entry (#280)', () => {
  const adminDetail = (): UserDetail =>
    ({
      userId: ADMIN,
      username: 'admin',
      signingPublicKey: b64(adminKey.publicKey),
      wrappingPublicKey: b64(WRAP_OLD),
      supersededSigningKeys: [],
      keyEpoch: 0,
      keyChanges: [],
    }) as UserDetail

  function withWrapper(read: (id: string) => Promise<UserDetail>) {
    const { deps } = setup()
    const getUserDetail = vi.fn(async (id: string) => (id === X ? served() : read(id)))
    return { deps: { ...deps, getUserDetail }, getUserDetail }
  }

  it('reports the admin whose signed record verifies', async () => {
    const { deps } = withWrapper(async () => adminDetail())
    const entry = { ...ENTRY, wrapRecord: recordBy(ADMIN, adminKey, 'approval') }
    expect(await prepareAcceptKeyChange(deps, X, { groupId: GROUP, entry })).toMatchObject({
      ok: true,
      wrap: { kind: 'approved', wrapperUserId: ADMIN },
    })
  })

  it('reports a self-wrap using the subject’s own served keys, without another read', async () => {
    const { deps, getUserDetail } = withWrapper(async () => adminDetail())
    const entry = { ...ENTRY, wrapRecord: recordBy(X, k1, 'self') }
    expect(await prepareAcceptKeyChange(deps, X, { groupId: GROUP, entry })).toMatchObject({
      wrap: { kind: 'self' },
    })
    expect(getUserDetail.mock.calls.filter(([id]) => id !== X)).toEqual([])
  })

  it('says unchecked, not none, when the wrapper’s keys cannot be read', async () => {
    const { deps } = withWrapper(async () => {
      throw new Error('boom')
    })
    const entry = { ...ENTRY, wrapRecord: recordBy(ADMIN, adminKey, 'approval') }
    const out = await prepareAcceptKeyChange(deps, X, { groupId: GROUP, entry })
    expect(out).toMatchObject({ ok: true, wrap: { kind: 'unchecked' } })
  })

  it('does not read the wrapper when the entry has no record', async () => {
    const { deps, getUserDetail } = withWrapper(async () => adminDetail())
    await prepareAcceptKeyChange(deps, X, CTX)
    expect(getUserDetail.mock.calls.filter(([id]) => id !== X)).toEqual([])
  })

  it('says invalid for a record signed for another generation', async () => {
    const { deps } = withWrapper(async () => adminDetail())
    const entry = { ...ENTRY, generation: 4, wrapRecord: recordBy(ADMIN, adminKey, 'approval') }
    expect(await prepareAcceptKeyChange(deps, X, { groupId: GROUP, entry })).toMatchObject({
      wrap: { kind: 'invalid' },
    })
  })

  it('says unchecked when the subject is not on the roster', async () => {
    const { deps } = setup()
    expect(
      await prepareAcceptKeyChange(deps, X, { groupId: GROUP, entry: undefined }),
    ).toMatchObject({ ok: true, wrap: { kind: 'unchecked' } })
  })
})
