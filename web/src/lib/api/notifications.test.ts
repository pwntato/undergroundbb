import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './auth'
import { getUnreadTotal } from './notifications'

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

describe('getUnreadTotal (#145)', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('GETs the unread endpoint with the session cookie and returns the two fields', async () => {
    const fetchMock = stubFetch(200, { unread: 4, unreadMore: true, extra: 1 })
    expect(await getUnreadTotal()).toEqual({ unread: 4, unreadMore: true })
    expect(fetchMock).toHaveBeenCalledWith('/api/notifications/unread', {
      credentials: 'same-origin',
    })
  })

  it('rejects a malformed answer rather than showing a made-up count', async () => {
    stubFetch(200, { unread: '4' })
    await expect(getUnreadTotal()).rejects.toBeInstanceOf(ApiError)
  })

  it('rejects an error status', async () => {
    stubFetch(500, { error: 'could not count unread notifications' })
    await expect(getUnreadTotal()).rejects.toMatchObject({ status: 500 })
  })
})
