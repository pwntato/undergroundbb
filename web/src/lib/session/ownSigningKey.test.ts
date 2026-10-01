import { describe, expect, it } from 'vitest'
import {
  cacheOwnSigningKey,
  clearCachedOwnSigningKey,
  ownSigningKeyWithFallback,
  readCachedOwnSigningKey,
  type KeyStorage,
} from './ownSigningKey'

function fakeStorage(): KeyStorage {
  const data = new Map<string, string>()
  return {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
    removeItem: (k) => void data.delete(k),
  }
}

const noKeys = () => Promise.reject(new Error('no live keys'))

describe('ownSigningKey', () => {
  it('round-trips and clears', () => {
    const s = fakeStorage()
    cacheOwnSigningKey('u1', 'a2V5', s)
    expect(readCachedOwnSigningKey('u1', s)).toBe('a2V5')
    clearCachedOwnSigningKey('u1', s)
    expect(readCachedOwnSigningKey('u1', s)).toBeNull()
  })

  it('never returns another account\'s key', () => {
    const s = fakeStorage()
    cacheOwnSigningKey('u1', 'a2V5', s)
    expect(readCachedOwnSigningKey('u2', s)).toBeNull()
  })

  it('prefers the worker over the cache', async () => {
    const s = fakeStorage()
    cacheOwnSigningKey('u1', 'stale', s)
    await expect(ownSigningKeyWithFallback('u1', () => Promise.resolve('live'), s)).resolves.toBe(
      'live',
    )
  })

  it('falls back to the cache when the worker has no live keys (after reload)', async () => {
    const s = fakeStorage()
    cacheOwnSigningKey('u1', 'a2V5', s)
    await expect(ownSigningKeyWithFallback('u1', noKeys, s)).resolves.toBe('a2V5')
  })

  it('rejects with the worker error when there is no cache', async () => {
    await expect(ownSigningKeyWithFallback('u1', noKeys, fakeStorage())).rejects.toThrow(
      'no live keys',
    )
  })

  it('survives unusable storage', async () => {
    const broken: KeyStorage = {
      getItem: () => {
        throw new Error('denied')
      },
      setItem: () => {
        throw new Error('denied')
      },
      removeItem: () => {
        throw new Error('denied')
      },
    }
    cacheOwnSigningKey('u1', 'k', broken)
    clearCachedOwnSigningKey('u1', broken)
    await expect(ownSigningKeyWithFallback('u1', noKeys, broken)).rejects.toThrow('no live keys')
  })
})
