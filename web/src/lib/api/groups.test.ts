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
import {
  CommentPathError,
  createComment,
  deleteReaction,
  getKeychain,
  listGroups,
  putReaction,
  removeMember,
} from './groups'

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
        startSignature: 'sig',
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

describe('getKeychain', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GETs the range with from and to in the query and returns the body', async () => {
    const body = { links: [{ generation: 1, wrapped: { nonce: 'bg==', ciphertext: 'Yw==' } }] }
    const fetchMock = stubFetch(200, body)
    expect(await getKeychain('g/1', 1, 3)).toEqual(body)
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/groups/g%2F1/keychain?from=1&to=3')
    expect(init.credentials).toBe('same-origin')
  })

  it('rejects with ApiError on a non-2xx response', async () => {
    stubFetch(404, { error: 'group not found' })
    await expect(getKeychain('g1', 0, 0)).rejects.toMatchObject({ status: 404 })
  })
})

describe('createComment', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  // Real Response objects: the 409 body is read twice (once for nextPath, once by
  // the shared error path), which a hand-made stub would not catch.
  const respond = (status: number, body: unknown) => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(body), { status }))
    vi.stubGlobal('fetch', fetchMock)
    return fetchMock
  }
  const req = {
    path: '0001',
    generation: 0,
    signedDay: '2026-10-29',
    nonce: 'n',
    ciphertext: 'c',
    signature: 's',
  }
  const POST = 'g#2026-10-29#00112233445566ff'

  it('POSTs the sealed comment to the post, with the # escaped', async () => {
    const fetchMock = respond(201, { path: '0001' })
    expect(await createComment(POST, req)).toEqual({ path: '0001' })
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/posts/g%232026-10-29%2300112233445566ff/comments')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body as string)).toEqual(req)
  })

  it.each(['comment_path_taken', 'comment_path_skips'])(
    'throws a CommentPathError carrying nextPath on %s',
    async (code) => {
      respond(409, { error: 'move on', code, nextPath: '0001.0004' })
      const err = await createComment(POST, req).catch((e: unknown) => e)
      expect(err).toBeInstanceOf(CommentPathError)
      expect(err).toMatchObject({ status: 409, code, nextPath: '0001.0004', message: 'move on' })
    },
  )

  it('keeps other 409 codes as a plain ApiError', async () => {
    respond(409, { error: 'full', code: 'replies_full' })
    const err = await createComment(POST, req).catch((e: unknown) => e)
    expect(err).not.toBeInstanceOf(CommentPathError)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 409, code: 'replies_full' })
  })

  it('ignores a nextPath that comes with any other code', async () => {
    respond(409, { error: 'full', code: 'replies_full', nextPath: '0001.0004' })
    const err = await createComment(POST, req).catch((e: unknown) => e)
    expect(err).not.toBeInstanceOf(CommentPathError)
    expect(err).toMatchObject({ status: 409, code: 'replies_full' })
  })

  it('does not treat a path conflict without a nextPath as one', async () => {
    respond(409, { error: 'x', code: 'comment_path_taken' })
    const err = await createComment(POST, req).catch((e: unknown) => e)
    expect(err).not.toBeInstanceOf(CommentPathError)
    expect(err).toMatchObject({ status: 409, code: 'comment_path_taken' })
  })
})

describe('reactions', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  const POST = 'g#2026-10-29#00112233445566ff'
  const body = { generation: 0, nonce: 'n', ciphertext: 'c' }
  // A real 204 has no body, which is what a JSON-only helper chokes on.
  const reply = (status: number, json?: unknown) => {
    const res =
      json === undefined
        ? new Response(null, { status })
        : new Response(JSON.stringify(json), { status })
    const fetchMock = vi.fn().mockResolvedValue(res)
    vi.stubGlobal('fetch', fetchMock)
    return fetchMock
  }

  it('PUTs the sealed reaction to the target, with the # escaped, and accepts a 204', async () => {
    const fetchMock = reply(204)
    await expect(putReaction(POST, '0001.0002', body)).resolves.toBeUndefined()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/posts/g%232026-10-29%2300112233445566ff/reactions/0001.0002')
    expect(init.method).toBe('PUT')
    expect(JSON.parse(init.body as string)).toEqual(body)
    expect(init.credentials).toBe('same-origin')
  })

  it('DELETEs the reaction on the post itself and accepts a 204', async () => {
    const fetchMock = reply(204)
    await expect(deleteReaction(POST, '0000')).resolves.toBeUndefined()
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/posts/g%232026-10-29%2300112233445566ff/reactions/0000')
    expect(init.method).toBe('DELETE')
  })

  it.each([
    [409, { error: 'retry', code: 'conflict_retry' }, 'conflict_retry'],
    [409, { error: 'gone', code: 'parent_gone' }, 'parent_gone'],
    [409, { error: 'stale', code: 'generation_stale' }, 'generation_stale'],
    [404, { error: 'no post' }, undefined],
    [401, { error: 'no session' }, undefined],
  ])('turns a %i into an ApiError carrying its code', async (status, json, code) => {
    reply(status, json)
    const err = await putReaction(POST, '0000', body).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status, code })
    reply(status, json)
    expect(await deleteReaction(POST, '0000').catch((e: unknown) => e)).toMatchObject({
      status,
      code,
    })
  })

  it('does not take a failed answer with no body for success', async () => {
    reply(502)
    expect(await putReaction(POST, '0000', body).catch((e: unknown) => e)).toMatchObject({
      status: 502,
    })
  })
})
