// Dependency-injected tests for runInvites.ts (node environment, no jsdom).

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { ReceivedInvite, SentInvite } from '@/lib/api/invites'
import { loadInvites, revokePending } from './runInvites'

const sent: SentInvite = {
  inviteId: 'i1',
  groupId: 'g1',
  expiresAt: '2026-10-05T23:59:59Z',
  accepted: false,
}
const received: ReceivedInvite = {
  inviteId: 'i2',
  groupId: 'g2',
  inviterUserId: 'u1',
  completionDeadline: '2026-10-06T23:59:59Z',
  removalDate: '2026-10-13T23:59:59Z',
}

describe('loadInvites', () => {
  it('returns both lists', async () => {
    const result = await loadInvites({
      sentInvites: () => Promise.resolve({ invites: [sent] }),
      receivedInvites: () => Promise.resolve({ invites: [received] }),
    })
    expect(result).toEqual({ ok: true, view: { sent: [sent], received: [received] } })
  })

  it('fails the whole load when either list fails, rather than showing half', async () => {
    const result = await loadInvites({
      sentInvites: () => Promise.resolve({ invites: [sent] }),
      receivedInvites: () => Promise.reject(new ApiError(500, 'boom')),
    })
    expect(result).toEqual({ ok: false, kind: 'failed' })
  })

  it('maps a 401 to authRequired', async () => {
    const result = await loadInvites({
      sentInvites: () => Promise.reject(new ApiError(401, 'nope')),
      receivedInvites: () => Promise.resolve({ invites: [] }),
    })
    expect(result).toEqual({ ok: false, kind: 'authRequired' })
  })

  it('treats a non-ApiError (network failure) as failed', async () => {
    const result = await loadInvites({
      sentInvites: () => Promise.reject(new TypeError('network')),
      receivedInvites: () => Promise.resolve({ invites: [] }),
    })
    expect(result).toEqual({ ok: false, kind: 'failed' })
  })
})

describe('revokePending', () => {
  it('revokes by id', async () => {
    const revokeInvite = vi.fn(() => Promise.resolve())
    expect(await revokePending({ revokeInvite }, 'i1')).toEqual({ ok: true })
    expect(revokeInvite).toHaveBeenCalledWith('i1')
  })

  it.each([
    [new ApiError(409, 'accepted', 'invite_already_accepted'), 'accepted'],
    [new ApiError(404, 'gone'), 'gone'],
    [new ApiError(401, 'expired'), 'authRequired'],
    [new ApiError(500, 'boom'), 'failed'],
    [new ApiError(409, 'other conflict', 'something_else'), 'failed'],
    [new TypeError('network'), 'failed'],
  ])('maps %s to %s', async (err, kind) => {
    const result = await revokePending({ revokeInvite: () => Promise.reject(err) }, 'i1')
    expect(result).toEqual({ ok: false, kind })
  })
})
