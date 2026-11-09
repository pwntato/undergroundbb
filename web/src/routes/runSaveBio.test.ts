import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { SAVE_BIO_ERRORS, saveBio } from './runSaveBio'

describe('saveBio', () => {
  it('sends the draft and returns what the server stored', async () => {
    const putBio = vi.fn().mockResolvedValue('trimmed')
    expect(await saveBio({ putBio }, ' trimmed ')).toEqual({ ok: true, bio: 'trimmed' })
    expect(putBio).toHaveBeenCalledExactlyOnceWith(' trimmed ')
  })
  it('refuses an over-long draft without calling the server', async () => {
    const putBio = vi.fn()
    expect(await saveBio({ putBio }, 'a'.repeat(281))).toEqual({ ok: false, kind: 'tooLong' })
    expect(putBio).not.toHaveBeenCalled()
  })
  it('maps the server answers', async () => {
    const fail = (status: number) => ({ putBio: () => Promise.reject(new ApiError(status, 'x')) })
    expect(await saveBio(fail(401), 'a')).toEqual({ ok: false, kind: 'authRequired' })
    expect(await saveBio(fail(404), 'a')).toEqual({ ok: false, kind: 'notFound' })
    expect(await saveBio(fail(400), 'a')).toEqual({ ok: false, kind: 'rejected' })
    expect(await saveBio(fail(500), 'a')).toEqual({ ok: false, kind: 'failed' })
    expect(await saveBio({ putBio: () => Promise.reject(new TypeError('offline')) }, 'a')).toEqual({
      ok: false,
      kind: 'failed',
    })
  })

  it('says emoji count against the limit, and that tabs and newlines are fine', () => {
    expect(SAVE_BIO_ERRORS.tooLong).toContain('emoji')
    expect(SAVE_BIO_ERRORS.rejected).toContain('tabs')
  })
  it('refuses 280 emoji, which fit the character cap but not the byte cap', async () => {
    const putBio = vi.fn()
    expect(await saveBio({ putBio }, '😀'.repeat(280))).toEqual({ ok: false, kind: 'tooLong' })
    expect(putBio).not.toHaveBeenCalled()
  })
})
