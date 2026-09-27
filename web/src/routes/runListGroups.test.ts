// Mirrors runCreateGroup.test.ts's dependency-injection structure -- see
// runListGroups.ts's own header comment for what this covers: the
// public/private split, the cache hit/miss paths (via a simple in-memory
// fake injected in place of groupNameCache.ts's real sessionStorage-backed
// functions -- this suite runs under vitest's `node` environment, not
// jsdom, so there is no global sessionStorage to test against directly,
// which is exactly why runListGroups.ts takes these as injected deps
// rather than importing groupNameCache.ts itself), and the two failure
// modes (isLiveKeysError vs. a per-group null result) neither of which may
// blank the rest of the list.

import { describe, expect, it, vi } from 'vitest'
import type { GroupListEntry } from '@/lib/api/groups'
import { isLiveKeysError, runListGroups, type ListGroupsDeps } from './runListGroups'

const USER_ID = 'user-1'

const WRAPPED_KEY = { ephemeralPub: 'ZXBoZW1lcmFs', nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' }
const NAME_CT = { nonce: 'bm9uY2Ux', ciphertext: 'bmFtZS1jdA==' }
const DESC_CT = { nonce: 'bm9uY2Uy', ciphertext: 'ZGVzYy1jdA==' }

function publicGroup(overrides: Partial<GroupListEntry> = {}): GroupListEntry {
  return {
    groupId: 'pub-1',
    visibility: 'public',
    role: 'admin',
    generation: 0,
    namePlaintext: 'Book Club',
    descriptionPlaintext: 'We read books',
    ...overrides,
  }
}

function privateGroup(overrides: Partial<GroupListEntry> = {}): GroupListEntry {
  return {
    groupId: 'priv-1',
    visibility: 'private',
    role: 'member',
    generation: 0,
    nameCiphertext: NAME_CT,
    descriptionCiphertext: DESC_CT,
    wrappedGroupKey: WRAPPED_KEY,
    ...overrides,
  }
}

/** A minimal in-memory stand-in for groupNameCache.ts's real functions, keyed exactly the same way. */
function fakeCache() {
  const store = new Map<
    string,
    { generation: number; name: string | null; description: string | null }
  >()
  return {
    getCachedGroupName: vi.fn(
      (
        userId: string,
        groupId: string,
        generation: number,
      ): { name: string | null; description: string | null } | null => {
        const entry = store.get(`${userId}:${groupId}`)
        if (!entry || entry.generation !== generation) {
          return null
        }
        return { name: entry.name, description: entry.description }
      },
    ),
    setCachedGroupName: vi.fn(
      (
        userId: string,
        groupId: string,
        generation: number,
        name: string | null,
        description: string | null,
      ): void => {
        store.set(`${userId}:${groupId}`, { generation, name, description })
      },
    ),
  }
}

function makeDeps(overrides: Partial<ListGroupsDeps> = {}): ListGroupsDeps {
  const cache = fakeCache()
  return {
    listGroups: vi.fn().mockResolvedValue({ groups: [] }),
    decryptGroupNames: vi.fn().mockResolvedValue([]),
    getCachedGroupName: cache.getCachedGroupName,
    setCachedGroupName: cache.setCachedGroupName,
    userId: USER_ID,
    ...overrides,
  }
}

describe('isLiveKeysError', () => {
  it('matches both of worker.ts decryptGroupNames own error messages', () => {
    expect(isLiveKeysError(new Error('worker: no live keys cached -- log in again'))).toBe(true)
    expect(
      isLiveKeysError(
        new Error('worker: cached keys belong to a different account than requested'),
      ),
    ).toBe(true)
    expect(isLiveKeysError(new Error('some other error'))).toBe(false)
    expect(isLiveKeysError('not an Error at all')).toBe(false)
  })
})

describe('runListGroups', () => {
  it('renders a public group directly from plaintext, with no decrypt call at all', async () => {
    const deps = makeDeps({ listGroups: vi.fn().mockResolvedValue({ groups: [publicGroup()] }) })

    const results = await runListGroups(deps)

    expect(results).toEqual([
      expect.objectContaining({
        groupId: 'pub-1',
        displayName: 'Book Club',
        displayDescription: 'We read books',
        nameStatus: 'plaintext',
      }),
    ])
    expect(deps.decryptGroupNames).not.toHaveBeenCalled()
  })

  it('decrypts a private group with no cache entry, then caches the result for the next call', async () => {
    const cache = fakeCache()
    const decryptGroupNames = vi
      .fn()
      .mockResolvedValue([{ groupId: 'priv-1', name: 'Roof Group', description: 'Talk' }])
    const deps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup()] }),
      decryptGroupNames,
      getCachedGroupName: cache.getCachedGroupName,
      setCachedGroupName: cache.setCachedGroupName,
    })

    const results = await runListGroups(deps)

    expect(results).toEqual([
      expect.objectContaining({
        groupId: 'priv-1',
        displayName: 'Roof Group',
        displayDescription: 'Talk',
        nameStatus: 'decrypted',
      }),
    ])
    expect(decryptGroupNames).toHaveBeenCalledWith({
      userId: USER_ID,
      groups: [
        {
          groupId: 'priv-1',
          generation: 0,
          wrappedGroupKey: WRAPPED_KEY,
          nameCiphertext: NAME_CT,
          descriptionCiphertext: DESC_CT,
        },
      ],
    })

    // A second call reusing the SAME cache (and the same generation) must
    // hit it and skip decryptGroupNames entirely -- the whole point of
    // caching per docs/DESIGN.md.
    const secondDecrypt = vi.fn()
    const secondDeps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup()] }),
      decryptGroupNames: secondDecrypt,
      getCachedGroupName: cache.getCachedGroupName,
      setCachedGroupName: cache.setCachedGroupName,
    })
    const secondResults = await runListGroups(secondDeps)
    expect(secondResults).toEqual([
      expect.objectContaining({ displayName: 'Roof Group', nameStatus: 'decrypted' }),
    ])
    expect(secondDecrypt).not.toHaveBeenCalled()
  })

  it('does not serve a cached entry from a different generation', async () => {
    const cache = fakeCache()
    cache.setCachedGroupName(USER_ID, 'priv-1', 0, 'Stale Name', 'Stale Desc')
    const decryptGroupNames = vi
      .fn()
      .mockResolvedValue([{ groupId: 'priv-1', name: 'Fresh Name', description: 'Fresh Desc' }])
    const deps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup({ generation: 1 })] }),
      decryptGroupNames,
      getCachedGroupName: cache.getCachedGroupName,
      setCachedGroupName: cache.setCachedGroupName,
    })

    const results = await runListGroups(deps)

    expect(results).toEqual([expect.objectContaining({ displayName: 'Fresh Name' })])
    expect(decryptGroupNames).toHaveBeenCalledTimes(1)
  })

  it('marks every private group coldKeys, without throwing, when liveKeys is cold', async () => {
    const deps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup(), publicGroup()] }),
      decryptGroupNames: vi.fn().mockRejectedValue(new Error('worker: no live keys cached')),
    })

    const results = await runListGroups(deps)

    expect(results).toEqual([
      expect.objectContaining({ groupId: 'priv-1', displayName: null, nameStatus: 'coldKeys' }),
      expect.objectContaining({
        groupId: 'pub-1',
        displayName: 'Book Club',
        nameStatus: 'plaintext',
      }),
    ])
  })

  it('rethrows a non-liveKeys decryptGroupNames failure', async () => {
    const deps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup()] }),
      decryptGroupNames: vi.fn().mockRejectedValue(new Error('worker: something else broke')),
    })

    await expect(runListGroups(deps)).rejects.toThrow('worker: something else broke')
  })

  it('marks a per-group decrypt failure unreadable without failing the rest of the batch', async () => {
    const deps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({
        groups: [privateGroup({ groupId: 'priv-good' }), privateGroup({ groupId: 'priv-bad' })],
      }),
      decryptGroupNames: vi.fn().mockResolvedValue([
        { groupId: 'priv-good', name: 'Good Group', description: 'Fine' },
        { groupId: 'priv-bad', name: null, description: null },
      ]),
    })

    const results = await runListGroups(deps)

    expect(results).toEqual([
      expect.objectContaining({
        groupId: 'priv-good',
        displayName: 'Good Group',
        nameStatus: 'decrypted',
      }),
      expect.objectContaining({ groupId: 'priv-bad', displayName: null, nameStatus: 'unreadable' }),
    ])
  })

  it('renders a private group missing a required field as unreadable, without calling decryptGroupNames for it', async () => {
    const { wrappedGroupKey: _omitted, ...malformed } = privateGroup()
    const deps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [malformed as GroupListEntry] }),
    })

    const results = await runListGroups(deps)

    expect(results).toEqual([
      expect.objectContaining({ displayName: null, nameStatus: 'unreadable' }),
    ])
    expect(deps.decryptGroupNames).not.toHaveBeenCalled()
  })
})
