import { beforeEach, describe, expect, it, vi } from 'vitest'
import { MAX_CONCURRENT_READS, clearUsernameCache, resolveUsernames } from './useUsernames'
import type { UserProjection } from '@/lib/api/users'

const user = (userId: string, username: string): UserProjection => ({
  userId,
  username,
  signingPublicKey: '',
  wrappingPublicKey: '',
  supersededSigningKeys: [],
})

describe('resolveUsernames', () => {
  beforeEach(clearUsernameCache)

  it('reads each distinct id once and caches across calls', async () => {
    const fetchUser = vi.fn((id: string) => Promise.resolve(user(id, `name-${id}`)))
    const first = await resolveUsernames(['a', 'b', 'a'], fetchUser)
    expect(first.get('a')).toBe('name-a')
    expect(first.get('b')).toBe('name-b')
    await resolveUsernames(['a', 'b', 'c'], fetchUser)
    expect(fetchUser.mock.calls.map((c) => c[0])).toEqual(['a', 'b', 'c'])
  })

  it('caches a deleted account as an empty username, not as unresolved', async () => {
    const fetchUser = vi.fn((id: string) =>
      Promise.resolve({ ...user(id, ''), deleted: true as const }),
    )
    const got = await resolveUsernames(['gone'], fetchUser)
    expect(got.has('gone')).toBe(true)
    expect(got.get('gone')).toBe('')
    await resolveUsernames(['gone'], fetchUser)
    expect(fetchUser).toHaveBeenCalledTimes(1)
  })

  it('leaves a failed read out of the map without throwing, and retries it next time', async () => {
    const fetchUser = vi
      .fn<(id: string) => Promise<UserProjection>>()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(user('a', 'alice'))
    expect((await resolveUsernames(['a'], fetchUser)).has('a')).toBe(false)
    expect((await resolveUsernames(['a'], fetchUser)).get('a')).toBe('alice')
  })

  it('never has more than the cap in flight and still resolves everything', async () => {
    let inFlight = 0
    let peak = 0
    const fetchUser = async (id: string) => {
      inFlight++
      peak = Math.max(peak, inFlight)
      await new Promise((r) => setTimeout(r, 1))
      inFlight--
      return user(id, `n-${id}`)
    }
    const ids = Array.from({ length: 50 }, (_, i) => `id${i}`)
    const got = await resolveUsernames(ids, fetchUser)
    expect(got.size).toBe(50)
    expect(peak).toBe(MAX_CONCURRENT_READS)
  })
})
