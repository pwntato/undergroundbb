import { afterEach, describe, expect, it, vi } from 'vitest'
import { USER_BATCH_SIZE, getUsers, type UserProjection } from './users'

const user = (userId: string): UserProjection => ({
  userId,
  username: `name-${userId}`,
  signingPublicKey: '',
  wrappingPublicKey: '',
  supersededSigningKeys: [],
})

function response(status: number, body: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    json: () => Promise.resolve(body),
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('getUsers', () => {
  it('asks once for a small set, deduplicated, and keys the answer by id', async () => {
    const fetchMock = vi.fn((_url: string, init: RequestInit) => {
      const { ids } = JSON.parse(init.body as string) as { ids: string[] }
      return Promise.resolve(response(200, { users: ids.filter((i) => i !== 'gone').map(user) }))
    })
    vi.stubGlobal('fetch', fetchMock)
    const got = await getUsers(['a', 'b', 'a', 'gone'])
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/api/users:batch')
    expect([...got.keys()].sort()).toEqual(['a', 'b'])
  })

  it('splits a large roster at the cap: 250 ids is 3 requests', async () => {
    const sizes: number[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        const { ids } = JSON.parse(init.body as string) as { ids: string[] }
        sizes.push(ids.length)
        return Promise.resolve(response(200, { users: ids.map(user) }))
      }),
    )
    const ids = Array.from({ length: 250 }, (_, i) => `id${i}`)
    const got = await getUsers(ids)
    expect(sizes).toEqual([USER_BATCH_SIZE, USER_BATCH_SIZE, 50])
    expect(got.size).toBe(250)
  })

  it('leaves the ids of a failed request absent without throwing, and keeps the others', async () => {
    let call = 0
    vi.stubGlobal(
      'fetch',
      vi.fn((_url: string, init: RequestInit) => {
        const { ids } = JSON.parse(init.body as string) as { ids: string[] }
        return Promise.resolve(
          ++call === 1
            ? response(503, { error: 'try again' })
            : response(200, { users: ids.map(user) }),
        )
      }),
    )
    const ids = Array.from({ length: 150 }, (_, i) => `id${i}`)
    const got = await getUsers(ids)
    expect(got.has('id0')).toBe(false)
    expect(got.has('id100')).toBe(true)
    expect(got.size).toBe(50)
  })

  it('treats a network error as unreadable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('Failed to fetch')))
    expect((await getUsers(['a'])).size).toBe(0)
  })

  it('ignores a projection the server was not asked for', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(response(200, { users: [user('a'), user('zzz')] })),
    )
    expect([...(await getUsers(['a'])).keys()]).toEqual(['a'])
  })

  it('makes no request for no ids', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    expect((await getUsers([])).size).toBe(0)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})
