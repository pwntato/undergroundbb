import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './auth'
import { listPublicGroups } from './directory'

function stubFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    headers: new Headers(),
    json: () => Promise.resolve(body),
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('listPublicGroups (#71)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('asks for the plain directory with no query string when nothing is set', async () => {
    const fetchMock = stubFetch(200, { groups: [] })
    expect(await listPublicGroups()).toEqual({ groups: [] })
    expect(fetchMock).toHaveBeenCalledWith('/api/groups/public', { credentials: 'same-origin' })
  })

  it('encodes the search, limit and cursor, so a name with # or & cannot change the request', async () => {
    const fetchMock = stubFetch(200, { groups: [] })
    await listPublicGroups({ q: 'A&B #1', limit: 25, cursor: 'NAME#A&B #1#id' })
    const url = fetchMock.mock.calls[0]?.[0] as string
    const params = new URL(url, 'http://x').searchParams
    expect(params.get('q')).toBe('A&B #1')
    expect(params.get('limit')).toBe('25')
    expect(params.get('cursor')).toBe('NAME#A&B #1#id')
    expect([...params.keys()].sort()).toEqual(['cursor', 'limit', 'q'])
  })

  it('returns entries and the next cursor, keeping duplicate names as separate entries', async () => {
    stubFetch(200, {
      groups: [
        { groupId: 'g1', name: 'Book Club', description: 'one' },
        { groupId: 'g2', name: 'Book Club' },
      ],
      nextCursor: 'c',
    })
    expect(await listPublicGroups()).toEqual({
      groups: [
        { groupId: 'g1', name: 'Book Club', description: 'one' },
        { groupId: 'g2', name: 'Book Club' },
      ],
      nextCursor: 'c',
    })
  })

  it('rejects a malformed page instead of showing a partial directory', async () => {
    for (const body of [
      {},
      { groups: 'x' },
      { groups: [{ name: 'n' }] },
      { groups: [{ groupId: 1, name: 'n' }] },
      { groups: [{ groupId: 'g', name: 5 }] },
      { groups: [{ groupId: 'g', name: 'n', description: 5 }] },
      { groups: [], nextCursor: 5 },
    ]) {
      stubFetch(200, body)
      await expect(listPublicGroups()).rejects.toBeInstanceOf(ApiError)
    }
  })

  it('rejects an error status with the server text', async () => {
    stubFetch(400, { error: 'limit: must be a number from 1 to 50' })
    await expect(listPublicGroups()).rejects.toMatchObject({
      status: 400,
      message: 'limit: must be a number from 1 to 50',
    })
  })
})
