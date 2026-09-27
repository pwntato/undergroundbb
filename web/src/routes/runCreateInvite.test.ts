// Mirrors runCreateGroup.test.ts's structure -- see runCreateInvite.ts's
// own header comment for what's the same and what genuinely differs (no
// client-chosen secret material here, only inviteId).

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { isDefinitelyUncommitted, runCreateInvite, type CreateInviteDeps } from './runCreateInvite'

const SIGN_RESULT = {
  creationSignature: 'Y3JlYXRpb24tc2ln',
  inviterFingerprint: '12345-67890-12345-67890-12345-67890-12345-67890-12345-67890-12345-67890',
}

const CREATE_RESPONSE = { inviteId: 'invite-1' }

function makeDeps(overrides: Partial<CreateInviteDeps> = {}): CreateInviteDeps {
  return {
    signInviteCreation: vi.fn().mockResolvedValue(SIGN_RESULT),
    createInvite: vi.fn().mockResolvedValue(CREATE_RESPONSE),
    userId: 'user-1',
    ...overrides,
  }
}

describe('isDefinitelyUncommitted', () => {
  const cases: { readonly err: unknown; readonly want: boolean }[] = [
    { err: new ApiError(400, 'bad request'), want: true },
    { err: new ApiError(401, 'unauthorized'), want: true },
    { err: new ApiError(403, 'forbidden'), want: true },
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

describe('runCreateInvite', () => {
  it('signs and submits, returning ok:true with the inviter fingerprint on success', async () => {
    const deps = makeDeps()
    const result = await runCreateInvite(deps, 'invite-1', 'group-1', '2026-10-03T00:00:00Z')

    expect(result).toEqual({
      ok: true,
      response: CREATE_RESPONSE,
      inviterFingerprint: SIGN_RESULT.inviterFingerprint,
    })
    expect(deps.signInviteCreation).toHaveBeenCalledWith({
      userId: 'user-1',
      inviteId: 'invite-1',
      groupId: 'group-1',
      expiresAt: '2026-10-03T00:00:00Z',
    })
    expect(deps.createInvite).toHaveBeenCalledWith('group-1', {
      inviteId: 'invite-1',
      expiresAt: '2026-10-03T00:00:00Z',
      creationSignature: SIGN_RESULT.creationSignature,
    })
  })

  it('signInviteCreation throwing is definitelyUncommitted (never reaches the network)', async () => {
    const deps = makeDeps({ signInviteCreation: vi.fn().mockRejectedValue(new Error('boom')) })
    const result = await runCreateInvite(deps, 'invite-1', 'group-1', '2026-10-03T00:00:00Z')
    expect(result).toEqual({ ok: false, kind: 'definitelyUncommitted', error: new Error('boom') })
    expect(deps.createInvite).not.toHaveBeenCalled()
  })

  it('a 401 from createInvite is authRequired', async () => {
    const deps = makeDeps({
      createInvite: vi.fn().mockRejectedValue(new ApiError(401, 'not authenticated')),
    })
    const result = await runCreateInvite(deps, 'invite-1', 'group-1', '2026-10-03T00:00:00Z')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('authRequired')
    }
  })

  it('a 403 from createInvite is forbidden, not ambiguous', async () => {
    const deps = makeDeps({
      createInvite: vi.fn().mockRejectedValue(new ApiError(403, 'must be an admin or ambassador')),
    })
    const result = await runCreateInvite(deps, 'invite-1', 'group-1', '2026-10-03T00:00:00Z')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('forbidden')
    }
  })

  it('a network failure from createInvite is ambiguous', async () => {
    const deps = makeDeps({
      createInvite: vi.fn().mockRejectedValue(new TypeError('fetch failed')),
    })
    const result = await runCreateInvite(deps, 'invite-1', 'group-1', '2026-10-03T00:00:00Z')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('ambiguous')
    }
  })

  it('a 500 from createInvite is ambiguous', async () => {
    const deps = makeDeps({
      createInvite: vi.fn().mockRejectedValue(new ApiError(500, 'internal error')),
    })
    const result = await runCreateInvite(deps, 'invite-1', 'group-1', '2026-10-03T00:00:00Z')
    expect(result.ok).toBe(false)
    if (!result.ok) {
      expect(result.kind).toBe('ambiguous')
    }
  })
})
