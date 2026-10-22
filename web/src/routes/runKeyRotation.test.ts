import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, GroupListEntry } from '@/lib/api/groups'
import { GroupsConflictError } from '@/lib/api/keyRotation'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { rosterEntryId } from '@/lib/crypto/key-rotation'
import type { SignedKeyRotation } from '@/lib/crypto/rotation-material'
import {
  preflightKeyRotation,
  runKeyRotation,
  type KeyRotationAttempt,
  type KeyRotationDeps,
  type KeyRotationPreflight,
  type KeyRotationStep,
} from './runKeyRotation'

const USER = 'user-1'
const WRAP = { ephemeralPub: 'ZXBo', nonce: 'bm9u', ciphertext: 'Y2lw' }
const NEW_WRAP_PUB = 'bmV3d3JhcA=='
const PARAMS = { memoryKiB: 1, iterations: 1, parallelism: 1 }
const BLOB = { nonce: 'bg==', ciphertext: 'Yw==' }

function group(id: string, over: Partial<GroupListEntry> = {}): GroupListEntry {
  return {
    groupId: id,
    visibility: 'private',
    role: 'admin',
    generation: 0,
    nameGeneration: 0,
    wrappedGroupKey: WRAP,
    ...over,
  }
}

const SIGNED: SignedKeyRotation = {
  signedDay: '2026-10-22',
  newSigningPublicKey: 'c2ln',
  newWrappingPublicKey: NEW_WRAP_PUB,
  roster: [],
  oldSignature: 'b2xk',
  newSignature: 'bmV3',
  credentials: {
    salt: 's',
    argon2Params: PARAMS,
    wrappedPrivateKeys: BLOB,
    recoverySalt: 'rs',
    recoveryArgon2Params: PARAMS,
    recoveryWrappedPrivateKeys: BLOB,
    recoveryVerifierSalt: 'vs',
    recoveryVerifierParams: PARAMS,
    recoveryVerifier: 'v',
    recoveryCode: 'ABCD-EFGH',
  },
}

function makeDeps(over: Partial<KeyRotationDeps> = {}, groups: GroupListEntry[] = [group('g1')]) {
  const deps: KeyRotationDeps = {
    hasLiveKeys: vi.fn().mockResolvedValue(true),
    getCredentials: vi.fn().mockResolvedValue({ userId: USER, credentialVersion: 4 }),
    getUser: vi
      .fn()
      .mockResolvedValue({ keyEpoch: 2, wrappingPublicKey: 'old', username: 'alice' }),
    // Serves the OLD credentials until a test says the rotation landed.
    challenge: vi
      .fn()
      .mockResolvedValue({ wrappedPrivateKeys: { nonce: 'old', ciphertext: 'old' } }),
    listGroups: vi.fn().mockResolvedValue({ groups }),
    getGroup: vi.fn().mockResolvedValue({ revocationMode: 'rotating' } as GroupDetail),
    sentInvites: vi.fn().mockResolvedValue({ invites: [] }),
    revokeInvite: vi.fn().mockResolvedValue(undefined),
    listAllPins: vi.fn().mockResolvedValue([]),
    listAllVerifications: vi.fn().mockResolvedValue([]),
    beginKeyRotation: vi
      .fn()
      .mockResolvedValue({ newSigningPublicKey: 'c2ln', newWrappingPublicKey: NEW_WRAP_PUB }),
    wrapHandoff: vi.fn().mockImplementation((r: { generation: number }) =>
      Promise.resolve({
        generation: r.generation,
        newWrappingPublicKey: NEW_WRAP_PUB,
        wrappedGroupKey: WRAP,
      }),
    ),
    putHandoff: vi.fn().mockResolvedValue(undefined),
    signKeyRotation: vi.fn().mockResolvedValue(SIGNED),
    rotateKeys: vi.fn().mockResolvedValue({ keyEpoch: 3, credentialVersion: 5 }),
    commitKeyRotation: vi.fn().mockResolvedValue(undefined),
    discardKeyRotation: vi.fn().mockResolvedValue(undefined),
    ...over,
  }
  return deps
}

function pre(over: Partial<KeyRotationPreflight> = {}): KeyRotationPreflight {
  return {
    userId: USER,
    username: 'alice',
    keyEpoch: 2,
    credentialVersion: 4,
    adminGroups: [
      { groupId: 'g1', generation: 0, wrappedGroupKey: WRAP, open: false, visibility: 'private' },
    ],
    invitesToRevoke: [],
    invitesAwaitingCompletion: 0,
    ...over,
  }
}

async function run(deps: KeyRotationDeps, attempt: KeyRotationAttempt = {}, p = pre()) {
  const steps: KeyRotationStep[] = []
  const result = await runKeyRotation(deps, p, 'a new password', attempt, {
    onStep: (s) => steps.push(s),
    onProgress: () => {},
  })
  return { result, steps }
}

const conflict = (code: string, groups: string[]) =>
  new GroupsConflictError('conflict', code, groups)

describe('preflightKeyRotation', () => {
  it('reports administered groups with their mode, and splits sent invites by whether anyone accepted', async () => {
    const deps = makeDeps(
      {
        getGroup: vi.fn().mockImplementation((id: string) =>
          Promise.resolve({
            revocationMode: id === 'open1' ? 'open' : 'rotating',
          } as GroupDetail),
        ),
        sentInvites: vi.fn().mockResolvedValue({
          invites: [
            { inviteId: 'i1', groupId: 'g1', expiresAt: '', accepted: false },
            { inviteId: 'i2', groupId: 'g1', expiresAt: '', accepted: true },
          ],
        }),
      },
      [
        group('g1'),
        group('open1', { generation: 3 }),
        group('member1', { role: 'member' }),
        group('pub1', { visibility: 'public' }),
      ],
    )
    const out = await preflightKeyRotation(deps)
    expect(out.keyEpoch).toBe(2)
    expect(out.credentialVersion).toBe(4)
    expect(out.adminGroups.map((g) => [g.groupId, g.open, g.generation])).toEqual([
      ['g1', false, 0],
      ['open1', true, 3],
      ['pub1', false, 0],
    ])
    expect(out.adminGroups.find((g) => g.groupId === 'pub1')?.visibility).toBe('public')
    expect(out.invitesToRevoke.map((i) => i.inviteId)).toEqual(['i1'])
    expect(out.invitesAwaitingCompletion).toBe(1)
  })
})

describe('runKeyRotation', () => {
  it('writes the handoffs, signs over the roster, commits, then switches the worker to the new keys', async () => {
    const sig = bytesToBase64(new Uint8Array(64).fill(7))
    const deps = makeDeps({
      listAllPins: vi.fn().mockResolvedValue([{ pinnedUserId: 'a', signature: sig }]),
      listAllVerifications: vi.fn().mockResolvedValue([{ verifiedUserId: 'b', signature: sig }]),
    })
    const { result, steps } = await run(deps)
    expect(result).toEqual({
      ok: true,
      recoveryCode: 'ABCD-EFGH',
      keyEpoch: 3,
      needsRelogin: false,
    })

    expect(deps.wrapHandoff).toHaveBeenCalledWith({
      userId: USER,
      groupId: 'g1',
      ownWrappedGroupKey: WRAP,
      generation: 0,
    })
    expect(deps.putHandoff).toHaveBeenCalledWith('g1', {
      generation: 0,
      newWrappingPublicKey: NEW_WRAP_PUB,
      wrappedGroupKey: WRAP,
    })
    const signCall = vi.mocked(deps.signKeyRotation).mock.calls[0]?.[0]
    expect(signCall?.expectedKeyEpoch).toBe(2)
    expect(signCall?.newPassword).toBe('a new password')
    const sigBytes = new Uint8Array(64).fill(7)
    expect(signCall?.roster).toEqual([
      bytesToBase64(rosterEntryId('PIN#a', sigBytes)),
      bytesToBase64(rosterEntryId('VERIFIED#b', sigBytes)),
    ])
    expect(vi.mocked(deps.rotateKeys).mock.calls[0]?.[0]).toMatchObject({
      expectedKeyEpoch: 2,
      expectedCredentialVersion: 4,
      signedDay: '2026-10-22',
      oldSignature: 'b2xk',
      newSignature: 'bmV3',
      recoveryVerifier: 'v',
    })
    // Order: handoff row before the rotation, the worker's switch after it.
    const order = (f: unknown) => vi.mocked(f as () => void).mock.invocationCallOrder[0] ?? 0
    expect(order(deps.putHandoff)).toBeLessThan(order(deps.rotateKeys))
    expect(order(deps.rotateKeys)).toBeLessThan(order(deps.commitKeyRotation))
    expect(deps.commitKeyRotation).toHaveBeenCalledWith(USER)
    expect(steps.map((s) => s.name)).toEqual([
      'preparing',
      'handoffs',
      'handoffs',
      'signing',
      'committing',
    ])
  })

  it('stops before doing anything when the worker has no live keys', async () => {
    const deps = makeDeps({ hasLiveKeys: vi.fn().mockResolvedValue(false) })
    const { result } = await run(deps)
    expect(result).toMatchObject({ ok: false, failure: { kind: 'needsLogin' } })
    expect(deps.beginKeyRotation).not.toHaveBeenCalled()
    expect(deps.revokeInvite).not.toHaveBeenCalled()
  })

  it('revokes unaccepted invites first, tolerating one accepted meanwhile', async () => {
    const deps = makeDeps({
      revokeInvite: vi
        .fn()
        .mockRejectedValueOnce(new ApiError(409, 'accepted', 'invite_already_accepted'))
        .mockResolvedValue(undefined),
    })
    const invites = [
      { inviteId: 'i1', groupId: 'g1', expiresAt: '', accepted: false },
      { inviteId: 'i2', groupId: 'g1', expiresAt: '', accepted: false },
    ]
    const { result } = await run(deps, {}, pre({ invitesToRevoke: invites }))
    expect(result.ok).toBe(true)
    expect(deps.revokeInvite).toHaveBeenCalledTimes(2)
    const order = (f: unknown) => vi.mocked(f as () => void).mock.invocationCallOrder[0] ?? 0
    expect(order(deps.revokeInvite)).toBeLessThan(order(deps.beginKeyRotation))
  })

  it('writes the rows a handoff_required names, then resends the same signed request', async () => {
    const deps = makeDeps(
      {
        rotateKeys: vi
          .fn()
          .mockRejectedValueOnce(conflict('handoff_required', ['g2']))
          .mockResolvedValue({ keyEpoch: 3, credentialVersion: 5 }),
      },
      [group('g1'), group('g2')],
    )
    const p = pre({
      adminGroups: [
        { groupId: 'g1', generation: 0, wrappedGroupKey: WRAP, open: false, visibility: 'private' },
        { groupId: 'g2', generation: 0, wrappedGroupKey: WRAP, open: false, visibility: 'private' },
      ],
    })
    const { result } = await run(deps, {}, p)
    expect(result.ok).toBe(true)
    // g1 and g2 up front, then g2 alone.
    expect(vi.mocked(deps.putHandoff).mock.calls.map((c) => c[0])).toEqual(['g1', 'g2', 'g2'])
    expect(deps.rotateKeys).toHaveBeenCalledTimes(2)
    expect(deps.signKeyRotation).toHaveBeenCalledTimes(1)
    const [a, b] = vi.mocked(deps.rotateKeys).mock.calls
    expect(a?.[0]).toBe(b?.[0])
  })

  it('rewrites every row when a handoff changed during the check, then resends', async () => {
    const deps = makeDeps(
      {
        rotateKeys: vi
          .fn()
          .mockRejectedValueOnce(new ApiError(409, 'changed', 'handoff_changed'))
          .mockResolvedValue({ keyEpoch: 3, credentialVersion: 5 }),
      },
      [group('g1'), group('g2')],
    )
    const p = pre({
      adminGroups: [
        { groupId: 'g1', generation: 0, wrappedGroupKey: WRAP, open: false, visibility: 'private' },
        { groupId: 'g2', generation: 0, wrappedGroupKey: WRAP, open: false, visibility: 'private' },
      ],
    })
    const { result } = await run(deps, {}, p)
    expect(result.ok).toBe(true)
    expect(vi.mocked(deps.putHandoff).mock.calls.map((c) => c[0])).toEqual(['g1', 'g2', 'g1', 'g2'])
  })

  it('gives up as groupBusy when handoffs keep changing', async () => {
    const deps = makeDeps({
      rotateKeys: vi.fn().mockRejectedValue(new ApiError(409, 'changed', 'handoff_changed')),
    })
    const { result } = await run(deps)
    expect(result).toMatchObject({ ok: false, failure: { kind: 'groupBusy' } })
    expect(deps.commitKeyRotation).not.toHaveBeenCalled()
  })

  it('re-reads a stale group once and retries, and calls a second refusal busy', async () => {
    const stale = new ApiError(409, 'moved', 'handoff_stale')
    const once = makeDeps({
      putHandoff: vi.fn().mockRejectedValueOnce(stale).mockResolvedValue(undefined),
    })
    expect((await run(once)).result.ok).toBe(true)
    expect(once.listGroups).toHaveBeenCalledTimes(2)
    expect(once.wrapHandoff).toHaveBeenCalledTimes(2)

    const twice = makeDeps({ putHandoff: vi.fn().mockRejectedValue(stale) })
    const { result } = await run(twice)
    expect(result).toMatchObject({ ok: false, failure: { kind: 'groupBusy', groups: ['g1'] } })
    expect(twice.rotateKeys).not.toHaveBeenCalled()
  })

  it('skips a group the caller no longer administers', async () => {
    const deps = makeDeps({}, [group('g1', { role: 'member' })])
    const { result } = await run(deps)
    expect(result.ok).toBe(true)
    expect(deps.putHandoff).not.toHaveBeenCalled()
  })

  it.each([
    ['the cooldown', new ApiError(429, 'later', 'rotation_cooldown'), { kind: 'cooldown' }],
    ['no session', new ApiError(401, 'no'), { kind: 'authRequired' }],
    [
      'a pending self re-key',
      conflict('handoff_pending', ['g1']),
      { kind: 'handoffPending', groups: ['g1'] },
    ],
    [
      'a key change under way',
      conflict('rotation_in_progress', ['g1']),
      { kind: 'groupBusy', groups: ['g1'] },
    ],
    ['stale keys', new ApiError(409, 'stale', 'key_epoch_stale'), { kind: 'changedElsewhere' }],
    ['changed credentials', new ApiError(409, 'changed'), { kind: 'changedElsewhere' }],
    [
      'a refusal',
      new ApiError(400, 'bad signature'),
      { kind: 'rejected', message: 'bad signature' },
    ],
  ])('classifies %s from rotate-keys and does not commit the worker', async (_n, err, want) => {
    const deps = makeDeps({ rotateKeys: vi.fn().mockRejectedValue(err) })
    const { result } = await run(deps)
    expect(result).toMatchObject({ ok: false, failure: want })
    expect(deps.commitKeyRotation).not.toHaveBeenCalled()
  })

  describe('when rotate-keys was sent and the answer is unknown', () => {
    const LANDED = { wrappedPrivateKeys: { nonce: BLOB.nonce, ciphertext: BLOB.ciphertext } }
    const dead = () => new ApiError(401, 'not authenticated')

    /** A server that commits, then loses the response and ends every session. */
    function landedThenLost(over: Partial<KeyRotationDeps> = {}) {
      let committed = false
      const gone = () => (committed ? Promise.reject(dead()) : undefined)
      const deps = makeDeps({
        rotateKeys: vi.fn().mockImplementation(() => {
          committed = true
          return Promise.reject(new TypeError('Failed to fetch'))
        }),
        // Everything that needs a session fails once the rotation landed.
        getUser: vi
          .fn()
          .mockImplementation(() => gone() ?? Promise.resolve({ keyEpoch: 2, username: 'alice' })),
        listGroups: vi
          .fn()
          .mockImplementation(() => gone() ?? Promise.resolve({ groups: [group('g1')] })),
        challenge: vi
          .fn()
          .mockImplementation(() =>
            Promise.resolve(
              committed ? LANDED : { wrappedPrivateKeys: { nonce: 'old', ciphertext: 'old' } },
            ),
          ),
        ...over,
      })
      return deps
    }

    it('settles a lost response from the login challenge, with no session, and shows the recovery code', async () => {
      const deps = landedThenLost()
      const { result } = await run(deps)
      expect(result).toEqual({
        ok: true,
        recoveryCode: 'ABCD-EFGH',
        keyEpoch: 3,
        needsRelogin: true,
      })
      expect(deps.commitKeyRotation).toHaveBeenCalledWith(USER)
      // It asked the unauthenticated endpoint, not one that needs the dead session.
      expect(deps.challenge).toHaveBeenCalledWith('alice')
      expect(deps.getUser).not.toHaveBeenCalled()
    })

    it('reports unconfirmed, never "keys unchanged", when the challenge still serves the old keys', async () => {
      const deps = makeDeps({ rotateKeys: vi.fn().mockRejectedValue(new TypeError('network')) })
      const attempt: KeyRotationAttempt = {}
      const { result } = await run(deps, attempt)
      expect(result).toMatchObject({
        ok: false,
        failure: { kind: 'unconfirmed', recoveryCode: 'ABCD-EFGH' },
      })
      expect(deps.commitKeyRotation).not.toHaveBeenCalled()
      // Everything needed to resume is kept.
      expect(attempt.ambiguous).toBe(true)
      expect(attempt.request).toBeDefined()
      expect(attempt.begun).toBeDefined()
    })

    it("only counts the rotation as landed when the served wrap is exactly this request's, nonce and ciphertext", async () => {
      for (const served of [
        { nonce: BLOB.nonce, ciphertext: 'other' },
        { nonce: 'other', ciphertext: BLOB.ciphertext },
      ]) {
        const deps = makeDeps({
          rotateKeys: vi.fn().mockRejectedValue(new TypeError('network')),
          challenge: vi.fn().mockResolvedValue({ wrappedPrivateKeys: served }),
        })
        const { result } = await run(deps)
        expect(result).toMatchObject({ ok: false, failure: { kind: 'unconfirmed' } })
        expect(deps.commitKeyRotation).not.toHaveBeenCalled()
      }
    })

    it('reports unconfirmed when the challenge itself cannot be read', async () => {
      const deps = makeDeps({
        rotateKeys: vi.fn().mockRejectedValue(new TypeError('network')),
        challenge: vi.fn().mockRejectedValue(new TypeError('network')),
      })
      const { result } = await run(deps)
      expect(result).toMatchObject({ ok: false, failure: { kind: 'unconfirmed' } })
    })

    it('does not read a later 401 as "nothing was rotated": the retry settles it as landed', async () => {
      // The reviewer's repro: first run unconfirmed (the read was stale), the
      // retry then meets a dead session.
      let landedNow = false
      const deps = landedThenLost({
        challenge: vi
          .fn()
          .mockImplementation(() =>
            Promise.resolve(
              landedNow ? LANDED : { wrappedPrivateKeys: { nonce: 'old', ciphertext: 'old' } },
            ),
          ),
      })
      const attempt: KeyRotationAttempt = {}
      const first = await run(deps, attempt)
      expect(first.result).toMatchObject({ ok: false, failure: { kind: 'unconfirmed' } })

      landedNow = true // the read has caught up
      const retry = await run(deps, attempt)
      expect(retry.result).toMatchObject({
        ok: true,
        needsRelogin: true,
        recoveryCode: 'ABCD-EFGH',
      })
      // The retry used no session: nothing before the send was repeated, and the
      // request was not sent a second time.
      expect(deps.listGroups).toHaveBeenCalledTimes(1)
      expect(deps.rotateKeys).toHaveBeenCalledTimes(1)
      expect(deps.commitKeyRotation).toHaveBeenCalledWith(USER)
    })

    it('treats a 401 or a stale epoch after an unknown send as unconfirmed or landed, never as a plain failure', async () => {
      for (const err of [
        dead(),
        new ApiError(409, 'stale', 'key_epoch_stale'),
        new ApiError(400, 'stale day'),
      ]) {
        const rotateKeys = vi
          .fn()
          .mockRejectedValueOnce(new TypeError('network'))
          .mockRejectedValue(err)
        const deps = makeDeps({ rotateKeys })
        const attempt: KeyRotationAttempt = {}
        await run(deps, attempt)
        const { result } = await run(deps, attempt)
        expect(result).toMatchObject({ ok: false, failure: { kind: 'unconfirmed' } })
      }
    })

    it('resends the same signed request on retry, and a first-send 401 is still a plain authRequired', async () => {
      const rotateKeys = vi
        .fn()
        .mockRejectedValueOnce(new TypeError('network'))
        .mockResolvedValue({ keyEpoch: 3, credentialVersion: 5 })
      const deps = makeDeps({ rotateKeys })
      const attempt: KeyRotationAttempt = {}
      await run(deps, attempt)
      const retry = await run(deps, attempt)
      expect(retry.result).toMatchObject({ ok: true, needsRelogin: false })
      expect(deps.beginKeyRotation).toHaveBeenCalledTimes(1)
      expect(deps.signKeyRotation).toHaveBeenCalledTimes(1)
      const [a, b] = rotateKeys.mock.calls
      expect(a?.[0]).toBe(b?.[0])

      // A 401 on the very first send is a definite answer: nothing was sent before it.
      const first = makeDeps({ rotateKeys: vi.fn().mockRejectedValue(dead()) })
      const { result } = await run(first)
      expect(result).toMatchObject({ ok: false, failure: { kind: 'authRequired' } })
    })

    it('does not ask for a password again on a retry: the request keeps the first one', async () => {
      const deps = makeDeps({
        rotateKeys: vi
          .fn()
          .mockRejectedValueOnce(new TypeError('network'))
          .mockResolvedValue({ keyEpoch: 3, credentialVersion: 5 }),
      })
      const attempt: KeyRotationAttempt = {}
      await run(deps, attempt)
      // The retry passes no password (the screen offers none) and signs nothing.
      const steps: KeyRotationStep[] = []
      const retry = await runKeyRotation(deps, pre(), '', attempt, {
        onStep: (s) => steps.push(s),
        onProgress: () => {},
      })
      expect(retry.ok).toBe(true)
      expect(deps.signKeyRotation).toHaveBeenCalledTimes(1)
      expect(vi.mocked(deps.signKeyRotation).mock.calls[0]?.[0].newPassword).toBe('a new password')
      expect(steps.map((s) => s.name)).toEqual(['committing'])
    })
  })

  it('shows the recovery code when the worker cannot switch keys after the server accepted', async () => {
    const deps = makeDeps({
      commitKeyRotation: vi.fn().mockRejectedValue(new Error('worker died')),
    })
    const { result } = await run(deps)
    expect(result).toEqual({ ok: true, recoveryCode: 'ABCD-EFGH', keyEpoch: 3, needsRelogin: true })
    expect(deps.rotateKeys).toHaveBeenCalledTimes(1)
  })
})
