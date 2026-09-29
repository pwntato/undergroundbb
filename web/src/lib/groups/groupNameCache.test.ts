// Direct test of groupNameCache.ts's own logic -- generation-match/mismatch,
// tolerating a missing/corrupt/blocked store, and per-user isolation. This
// suite runs under vitest's `node` environment (vitest.config.ts), which has
// no global sessionStorage at all (SignupProgressStep.test.tsx's own header
// comment explains why this codebase avoids jsdom generally) -- unlike
// runListGroups.test.ts, which sidesteps this by taking these functions as
// injected deps, this file needs the REAL functions under test, so it
// stubs globalThis.sessionStorage with a minimal in-memory Storage-shaped
// object for the duration of each test, restoring the original afterward.

import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import {
  clearGroupNameCache,
  getCachedGroupName,
  nameStamp,
  setCachedGroupName,
} from './groupNameCache'

function fakeStorage(): Storage {
  const data = new Map<string, string>()
  return {
    getItem: (key: string) => data.get(key) ?? null,
    setItem: (key: string, value: string) => {
      data.set(key, value)
    },
    removeItem: (key: string) => {
      data.delete(key)
    },
    clear: () => {
      data.clear()
    },
    key: (index: number) => Array.from(data.keys())[index] ?? null,
    get length() {
      return data.size
    },
  }
}

const originalSessionStorage = globalThis.sessionStorage as Storage | undefined

beforeEach(() => {
  Object.defineProperty(globalThis, 'sessionStorage', { value: fakeStorage(), configurable: true })
})

afterEach(() => {
  Object.defineProperty(globalThis, 'sessionStorage', {
    value: originalSessionStorage,
    configurable: true,
  })
})

describe('groupNameCache', () => {
  it('returns null on a cold cache', () => {
    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')).toBeNull()
  })

  it('round-trips a stored entry at the same generation', () => {
    setCachedGroupName('user-1', 'group-1', 0, 's1', 'Roof Group', 'Talk')
    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')).toEqual({
      name: 'Roof Group',
      description: 'Talk',
    })
  })

  it('round-trips a null-fields entry (a cached decrypt failure)', () => {
    setCachedGroupName('user-1', 'group-1', 0, 's1', null, null)
    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')).toEqual({
      name: null,
      description: null,
    })
  })

  it('treats a generation mismatch as a miss, not a stale hit', () => {
    setCachedGroupName('user-1', 'group-1', 0, 's1', 'Old Name', 'Old Desc')
    expect(getCachedGroupName('user-1', 'group-1', 1, 's1')).toBeNull()
  })

  it('treats a stamp mismatch as a miss: another admin re-sealed the name at the same generation', () => {
    setCachedGroupName('user-1', 'group-1', 0, 'nonceA:nonceB', 'Old Name', 'Old Desc')
    expect(getCachedGroupName('user-1', 'group-1', 0, 'nonceA:nonceB')?.name).toBe('Old Name')
    expect(getCachedGroupName('user-1', 'group-1', 0, 'nonceC:nonceD')).toBeNull()
  })

  it('treats an entry written before stamps existed as a miss', () => {
    sessionStorage.setItem(
      'undergroundbb:groupNameCache:user-1',
      JSON.stringify({ 'group-1': { generation: 0, name: 'Old', description: 'Old' } }),
    )
    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')).toBeNull()
  })

  it('nameStamp differs whenever either nonce differs', () => {
    expect(nameStamp({ nonce: 'a' }, { nonce: 'b' })).not.toBe(
      nameStamp({ nonce: 'a' }, { nonce: 'c' }),
    )
    expect(nameStamp({ nonce: 'a' }, { nonce: 'b' })).not.toBe(
      nameStamp({ nonce: 'x' }, { nonce: 'b' }),
    )
    expect(nameStamp({ nonce: 'a' }, { nonce: 'b' })).toBe(
      nameStamp({ nonce: 'a' }, { nonce: 'b' }),
    )
  })

  it('keeps different groups under the same user independent', () => {
    setCachedGroupName('user-1', 'group-1', 0, 's1', 'Group One', 'Desc One')
    setCachedGroupName('user-1', 'group-2', 0, 's1', 'Group Two', 'Desc Two')
    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')?.name).toBe('Group One')
    expect(getCachedGroupName('user-1', 'group-2', 0, 's1')?.name).toBe('Group Two')
  })

  it('keeps different users fully isolated, even for the same groupId', () => {
    setCachedGroupName('user-1', 'group-1', 0, 's1', 'User One Sees This', null)
    expect(getCachedGroupName('user-2', 'group-1', 0, 's1')).toBeNull()
  })

  it('clearGroupNameCache removes every entry for that user only', () => {
    setCachedGroupName('user-1', 'group-1', 0, 's1', 'Name', 'Desc')
    setCachedGroupName('user-2', 'group-1', 0, 's1', 'Other Name', 'Other Desc')

    clearGroupNameCache('user-1')

    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')).toBeNull()
    expect(getCachedGroupName('user-2', 'group-1', 0, 's1')).toEqual({
      name: 'Other Name',
      description: 'Other Desc',
    })
  })

  it('tolerates corrupt JSON in the store as a cache miss, not a throw', () => {
    sessionStorage.setItem('undergroundbb:groupNameCache:user-1', 'not valid json{{{')
    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')).toBeNull()
  })

  it('tolerates a store that throws on every call (private-browsing/blocked storage)', () => {
    Object.defineProperty(globalThis, 'sessionStorage', {
      value: {
        getItem: () => {
          throw new Error('storage disabled')
        },
        setItem: () => {
          throw new Error('storage disabled')
        },
        removeItem: () => {
          throw new Error('storage disabled')
        },
      },
      configurable: true,
    })

    expect(() => setCachedGroupName('user-1', 'group-1', 0, 's1', 'Name', 'Desc')).not.toThrow()
    expect(getCachedGroupName('user-1', 'group-1', 0, 's1')).toBeNull()
    expect(() => clearGroupNameCache('user-1')).not.toThrow()
  })
})
