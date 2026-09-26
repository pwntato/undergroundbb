// Mirrors runChangePassword.test.ts's structure -- see runCreateGroup.ts's
// own header comment for what's the same and what genuinely differs here
// (groupId/group-key generation and retry caching live in
// CreateGroupScreen, not in this function, unlike runChangePassword's fully
// self-contained flow).

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { isDefinitelyUncommitted, runCreateGroup, type CreateGroupDeps } from './runCreateGroup'

const SIGN_RESULT = {
  trustAnchorSignature: 'YW5jaG9yLXNpZw==',
  rootGrantSignature: 'Z3JhbnQtc2ln',
  groupKeyWrapped: {
    ephemeralPub: 'ZXBoZW1lcmFsLXB1Yg==',
    nonce: 'bm9uY2U=',
    ciphertext: 'Y2lwaGVy',
  },
}

const CREATE_RESPONSE = { groupId: 'group-1', rootGrantSortKey: 'GRANT#creator#2026-09-25#aaaa' }

const FORM = {
  visibility: 'private' as const,
  nameCiphertext: { nonce: 'bm9uY2U=', ciphertext: 'bmFtZQ==' },
  descriptionCiphertext: { nonce: 'bm9uY2U=', ciphertext: 'ZGVzYw==' },
  revocationMode: 'rotating' as const,
  expirationDays: 30,
}

function makeDeps(overrides: Partial<CreateGroupDeps> = {}): CreateGroupDeps {
  return {
    signGroupCreation: vi.fn().mockResolvedValue(SIGN_RESULT),
    createGroup: vi.fn().mockResolvedValue(CREATE_RESPONSE),
    userId: 'user-1',
    ...overrides,
  }
}

describe('isDefinitelyUncommitted', () => {
  const cases: { readonly err: unknown; readonly want: boolean }[] = [
    { err: new ApiError(400, 'bad request'), want: true },
    { err: new ApiError(401, 'unauthorized'), want: true },
    { err: new ApiError(409, 'group id taken', 'group_id_taken'), want: true },
    { err: new ApiError(500, 'internal error'), want: false },
    { err: new TypeError('network error'), want: false },
    { err: new Error('worker: no live keys cached'), want: false },
  ]
  for (const { err, want } of cases) {
    it(`${err instanceof Error ? err.message : String(err)} -> ${String(want)}`, () => {
      expect(isDefinitelyUncommitted(err)).toBe(want)
    })
  }
})

describe('runCreateGroup', () => {
  it('signs and submits, returning ok:true on success', async () => {
    const deps = makeDeps()
    const result = await runCreateGroup(deps, 'group-1', 'Z3JvdXBrZXk=', FORM)

    expect(result).toEqual({ ok: true, response: CREATE_RESPONSE })
    expect(deps.signGroupCreation).toHaveBeenCalledWith({
      userId: 'user-1',
      groupId: 'group-1',
      groupKey: 'Z3JvdXBrZXk=',
    })
    expect(deps.createGroup).toHaveBeenCalledWith({
      groupId: 'group-1',
      visibility: 'private',
      nameCiphertext: FORM.nameCiphertext,
      descriptionCiphertext: FORM.descriptionCiphertext,
      revocationMode: 'rotating',
      expirationDays: 30,
      groupKeyWrapped: SIGN_RESULT.groupKeyWrapped,
      trustAnchorSignature: SIGN_RESULT.trustAnchorSignature,
      rootGrantSignature: SIGN_RESULT.rootGrantSignature,
    })
  })

  it('omits plaintext fields for a private group and includes them for a public one', async () => {
    const deps = makeDeps()
    await runCreateGroup(deps, 'group-1', 'Z3JvdXBrZXk=', {
      visibility: 'public',
      namePlaintext: 'Book Club',
      descriptionPlaintext: 'We read books',
      revocationMode: 'open',
      expirationDays: 0,
    })

    const call = vi.mocked(deps.createGroup).mock.calls[0]?.[0]
    expect(call).toMatchObject({
      visibility: 'public',
      namePlaintext: 'Book Club',
      descriptionPlaintext: 'We read books',
    })
    expect(call).not.toHaveProperty('nameCiphertext')
    expect(call).not.toHaveProperty('descriptionCiphertext')
  })

  it('classifies a signing failure as definitelyUncommitted', async () => {
    const deps = makeDeps({ signGroupCreation: vi.fn().mockRejectedValue(new Error('boom')) })
    const result = await runCreateGroup(deps, 'group-1', 'Z3JvdXBrZXk=', FORM)

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('definitelyUncommitted')
    }
    expect(deps.createGroup).not.toHaveBeenCalled()
  })

  it('classifies a 401 from createGroup as authRequired', async () => {
    const deps = makeDeps({
      createGroup: vi.fn().mockRejectedValue(new ApiError(401, 'not authenticated')),
    })
    const result = await runCreateGroup(deps, 'group-1', 'Z3JvdXBrZXk=', FORM)

    expect(result).toEqual({
      ok: false,
      kind: 'authRequired',
      error: expect.any(ApiError),
    })
  })

  it('classifies a groupId conflict (409) from createGroup as definitelyUncommitted', async () => {
    const deps = makeDeps({
      createGroup: vi
        .fn()
        .mockRejectedValue(new ApiError(409, 'groupId is taken', 'group_id_taken')),
    })
    const result = await runCreateGroup(deps, 'group-1', 'Z3JvdXBrZXk=', FORM)

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('definitelyUncommitted')
    }
  })

  it('classifies a network failure from createGroup as ambiguous', async () => {
    const deps = makeDeps({ createGroup: vi.fn().mockRejectedValue(new TypeError('fetch failed')) })
    const result = await runCreateGroup(deps, 'group-1', 'Z3JvdXBrZXk=', FORM)

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('ambiguous')
    }
  })

  it('classifies a 5xx from createGroup as ambiguous', async () => {
    const deps = makeDeps({
      createGroup: vi.fn().mockRejectedValue(new ApiError(500, 'internal error')),
    })
    const result = await runCreateGroup(deps, 'group-1', 'Z3JvdXBrZXk=', FORM)

    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('ambiguous')
    }
  })
})
