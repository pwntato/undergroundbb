import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './auth'
import {
  deleteHandoff,
  GroupsConflictError,
  listHandoffs,
  putHandoff,
  rotateKeys,
  type RotateKeysRequest,
} from './keyRotation'

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

afterEach(() => {
  vi.unstubAllGlobals()
})

const WRAP = { ephemeralPub: 'a', nonce: 'b', ciphertext: 'c' }
const PUT = { generation: 2, newWrappingPublicKey: 'k', wrappedGroupKey: WRAP }

describe('handoff rows', () => {
  it('PUTs the row at the group path with a JSON body', async () => {
    const fetchMock = stubFetch(204, null)
    await putHandoff('g/1', PUT)
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/account/rotation-handoff/g%2F1')
    expect(init.method).toBe('PUT')
    expect(JSON.parse(init.body as string)).toEqual(PUT)
    expect(init.credentials).toBe('same-origin')
  })

  it('DELETEs and lists', async () => {
    const del = stubFetch(204, null)
    await deleteHandoff('g1')
    expect((del.mock.calls[0] as [string, RequestInit])[1].method).toBe('DELETE')

    const entry = { groupId: 'g1', generation: 0, newWrappingPublicKey: 'k', wrappedGroupKey: WRAP }
    const list = stubFetch(200, { handoffs: [entry] })
    expect(await listHandoffs()).toEqual([entry])
    expect(list.mock.calls[0]?.[0]).toBe('/api/account/rotation-handoff')
  })

  it('carries the code of a refusal', async () => {
    stubFetch(409, { error: 'moved', code: 'handoff_stale' })
    await expect(putHandoff('g1', PUT)).rejects.toMatchObject({
      status: 409,
      code: 'handoff_stale',
    })
  })
})

describe('rotateKeys', () => {
  const REQ = { expectedKeyEpoch: 0 } as unknown as RotateKeysRequest

  it('POSTs to rotate-keys and returns the new epoch', async () => {
    const fetchMock = stubFetch(200, { keyEpoch: 1, credentialVersion: 2 })
    expect(await rotateKeys(REQ)).toEqual({ keyEpoch: 1, credentialVersion: 2 })
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(url).toBe('/api/account/rotate-keys')
    expect(init.method).toBe('POST')
  })

  it('turns a 409 that names groups into a GroupsConflictError carrying them', async () => {
    stubFetch(409, { error: 'write a handoff', code: 'handoff_required', groups: ['g1', 'g2'] })
    const err = await rotateKeys(REQ).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(GroupsConflictError)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 409, code: 'handoff_required', groups: ['g1', 'g2'] })
  })

  it('keeps a plain ApiError for a 409 without groups, and for other statuses', async () => {
    stubFetch(409, { error: 'changed', code: 'handoff_changed' })
    const changed = await rotateKeys(REQ).catch((e: unknown) => e)
    expect(changed).not.toBeInstanceOf(GroupsConflictError)
    expect(changed).toMatchObject({ status: 409, code: 'handoff_changed' })

    stubFetch(429, { error: 'later', code: 'rotation_cooldown' })
    expect(await rotateKeys(REQ).catch((e: unknown) => e)).toMatchObject({
      status: 429,
      code: 'rotation_cooldown',
    })
  })

  it('falls back to the status text when the body is not JSON', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 502,
        statusText: 'Bad Gateway',
        json: () => Promise.reject(new Error('not json')),
      }),
    )
    expect(await rotateKeys(REQ).catch((e: unknown) => e)).toMatchObject({
      status: 502,
      message: 'Bad Gateway',
    })
  })
})
