import { beforeEach, describe, expect, it, vi } from 'vitest'
import { clearUsernameCache, resolveUsernames } from './useUsernames'
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

  it('leaves a failed read out of the map without throwing, and retries it next time', async () => {
    const fetchUser = vi
      .fn<(id: string) => Promise<UserProjection>>()
      .mockRejectedValueOnce(new Error('boom'))
      .mockResolvedValueOnce(user('a', 'alice'))
    expect((await resolveUsernames(['a'], fetchUser)).has('a')).toBe(false)
    expect((await resolveUsernames(['a'], fetchUser)).get('a')).toBe('alice')
  })
})
