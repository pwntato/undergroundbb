import { describe, expect, it, vi } from 'vitest'
import { checkLiveKeys } from './useLiveKeys'

describe('checkLiveKeys', () => {
  it('is warm when the worker says warm, and asks about that user', async () => {
    const check = vi.fn(() => Promise.resolve(true))
    expect(await checkLiveKeys('u1', check)).toBe('warm')
    expect(check).toHaveBeenCalledWith('u1')
  })

  it('is cold only when the worker says cold', async () => {
    expect(await checkLiveKeys('u1', () => Promise.resolve(false))).toBe('cold')
  })

  it('falls back to warm when the check itself fails, so the submit-time handling still applies', async () => {
    expect(await checkLiveKeys('u1', () => Promise.reject(new Error('worker crashed')))).toBe(
      'warm',
    )
  })
})
