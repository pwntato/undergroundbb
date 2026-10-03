// Direct stubbed-fetch test of listGroups -- see auth.test.ts's own header
// comment for why this codebase's usual convention (inject the request
// function as an already-resolved/rejected dependency, e.g.
// runCreateGroup.test.ts) doesn't reach the request itself. listGroups is
// the one GET in this file (createGroup's own header comment notes every
// other endpoint here goes through putOrPostJSON), so this also pins that
// it hits GET /api/groups with no body, not the POST/PUT shape every other
// call in this file uses.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './auth'
import { listGroups, removeMember } from './groups'

function stubFetch(status: number, body: unknown) {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    statusText: '',
    json: () => Promise.resolve(body),
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

describe('listGroups', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GETs /api/groups with no body and returns the parsed groups list', async () => {
    const response = {
      groups: [
        {
          groupId: 'g1',
          visibility: 'public',
          role: 'admin',
          generation: 0,
          namePlaintext: 'Book Club',
        },
      ],
    }
    const fetchMock = stubFetch(200, response)

    const result = await listGroups()

    expect(result).toEqual(response)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/groups')
    expect(init.method ?? 'GET').toBe('GET')
    expect(init.body).toBeUndefined()
    expect(init.credentials).toBe('same-origin')
  })

  it('rejects with ApiError on a non-2xx response', async () => {
    stubFetch(401, { error: 'not authenticated' })

    await expect(listGroups()).rejects.toMatchObject({
      status: 401,
      message: 'not authenticated',
    })
  })

  it('returns an empty list for a user in no groups', async () => {
    stubFetch(200, { groups: [] })

    const result = await listGroups()

    expect(result.groups).toEqual([])
  })
})

describe('removeMember', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('DELETEs the member path with no body when there is nothing to attach', async () => {
    const fetchMock = stubFetch(204, null)
    await removeMember('g 1', 'u/2')
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/groups/g%201/members/u%2F2')
    expect(init.method).toBe('DELETE')
    expect(init.body).toBeUndefined()
  })

  it('sends the demotion and rotation as the JSON body', async () => {
    const fetchMock = stubFetch(204, null)
    const req = {
      grantSortKey: 'GRANT#k',
      grantorGrantRef: 'GRANT#r',
      signature: 's',
      rotation: {
        generation: 2,
        link: { nonce: 'n', ciphertext: 'c' },
        removerWrappedKey: { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' },
      },
    }
    await removeMember('g1', 'u2', req)
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(init.body as string)).toEqual(req)
  })

  it('rejects with the server code on a 409', async () => {
    stubFetch(409, { error: 'busy', code: 'rotation_in_progress' })
    await expect(removeMember('g1', 'u2')).rejects.toMatchObject({
      status: 409,
      code: 'rotation_in_progress',
    })
    stubFetch(409, { error: 'busy', code: 'rotation_in_progress' })
    await expect(removeMember('g1', 'u2')).rejects.toBeInstanceOf(ApiError)
  })
})
