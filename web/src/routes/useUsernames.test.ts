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

/** A getUsers stand-in that knows every id except those in `unknown`. */
const fetchUsers = (unknown: readonly string[] = []) =>
  vi.fn((ids: readonly string[]) =>
    Promise.resolve(
      new Map(ids.filter((id) => !unknown.includes(id)).map((id) => [id, user(id, `name-${id}`)])),
    ),
  )

describe('resolveUsernames', () => {
  beforeEach(clearUsernameCache)

  it('asks for the distinct unknown ids in one call and caches across calls', async () => {
    const fetch = fetchUsers()
    const first = await resolveUsernames(['a', 'b', 'a'], fetch)
    expect(first.get('a')).toBe('name-a')
    expect(first.get('b')).toBe('name-b')
    expect(fetch).toHaveBeenCalledTimes(1)
    expect(fetch.mock.calls[0]?.[0]).toEqual(['a', 'b'])
    await resolveUsernames(['a', 'b', 'c'], fetch)
    expect(fetch).toHaveBeenCalledTimes(2)
    expect(fetch.mock.calls[1]?.[0]).toEqual(['c'])
  })

  it('makes no call when everything is cached', async () => {
    const fetch = fetchUsers()
    await resolveUsernames(['a'], fetch)
    await resolveUsernames(['a'], fetch)
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('caches a deleted account as an empty username, not as unresolved', async () => {
    // The server sends an empty username for a tombstone; the flag is what
    // decides, so a stray non-empty one must not be shown as a person.
    const fetch = vi.fn((ids: readonly string[]) =>
      Promise.resolve(
        new Map(ids.map((id) => [id, { ...user(id, 'stale-name'), deleted: true as const }])),
      ),
    )
    const got = await resolveUsernames(['gone'], fetch)
    expect(got.has('gone')).toBe(true)
    expect(got.get('gone')).toBe('')
    await resolveUsernames(['gone'], fetch)
    expect(fetch).toHaveBeenCalledTimes(1)
  })

  it('leaves an id the server did not return out of the map, and retries it next time', async () => {
    const fetch = vi
      .fn<(ids: readonly string[]) => Promise<ReadonlyMap<string, UserProjection>>>()
      .mockResolvedValueOnce(new Map())
      .mockResolvedValueOnce(new Map([['a', user('a', 'alice')]]))
    expect((await resolveUsernames(['a'], fetch)).has('a')).toBe(false)
    expect((await resolveUsernames(['a'], fetch)).get('a')).toBe('alice')
  })

  it('resolves the ones it got and leaves the rest when only some come back', async () => {
    const got = await resolveUsernames(['a', 'x', 'b'], fetchUsers(['x']))
    expect([...got.keys()].sort()).toEqual(['a', 'b'])
  })

  it('does not throw if the batch call itself rejects', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('boom'))
    expect((await resolveUsernames(['a'], fetch)).size).toBe(0)
  })
})
