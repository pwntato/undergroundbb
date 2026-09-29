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
    nameGeneration: 0,
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
    nameGeneration: 0,
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
          nameGeneration: 0,
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

  it('does not serve a cached entry from a different name generation', async () => {
    const cache = fakeCache()
    cache.setCachedGroupName(USER_ID, 'priv-1', 0, 'Stale Name', 'Stale Desc')
    const decryptGroupNames = vi
      .fn()
      .mockResolvedValue([{ groupId: 'priv-1', name: 'Fresh Name', description: 'Fresh Desc' }])
    const deps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup({ nameGeneration: 1 })] }),
      decryptGroupNames,
      getCachedGroupName: cache.getCachedGroupName,
      setCachedGroupName: cache.setCachedGroupName,
    })

    const results = await runListGroups(deps)

    expect(results).toEqual([expect.objectContaining({ displayName: 'Fresh Name' })])
    expect(decryptGroupNames).toHaveBeenCalledTimes(1)
  })

  it('keys the cache and the decrypt on nameGeneration, not the member generation', async () => {
    // Once rotation exists a member's generation moves on while the name
    // stays sealed under its original generation: an entry cached at
    // nameGeneration 0 must still hit, and decrypt must be handed both.
    const cache = fakeCache()
    cache.setCachedGroupName(USER_ID, 'priv-1', 0, 'Cached Name', 'Cached Desc')
    const decryptGroupNames = vi.fn()
    const hit = await runListGroups(
      makeDeps({
        listGroups: vi
          .fn()
          .mockResolvedValue({ groups: [privateGroup({ generation: 4, nameGeneration: 0 })] }),
        decryptGroupNames,
        getCachedGroupName: cache.getCachedGroupName,
        setCachedGroupName: cache.setCachedGroupName,
      }),
    )
    expect(hit).toEqual([expect.objectContaining({ displayName: 'Cached Name' })])
    expect(decryptGroupNames).not.toHaveBeenCalled()

    const miss = vi.fn().mockResolvedValue([{ groupId: 'priv-1', name: 'N', description: 'D' }])
    await runListGroups(
      makeDeps({
        listGroups: vi
          .fn()
          .mockResolvedValue({ groups: [privateGroup({ generation: 4, nameGeneration: 2 })] }),
        decryptGroupNames: miss,
        getCachedGroupName: cache.getCachedGroupName,
        setCachedGroupName: cache.setCachedGroupName,
      }),
    )
    expect(miss).toHaveBeenCalledWith({
      userId: USER_ID,
      groups: [expect.objectContaining({ generation: 4, nameGeneration: 2 })],
    })
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

    // Order-independent -- this test is about the batch not failing, not
    // about final list order (sortByLabel's own tests cover ordering).
    expect(results).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          groupId: 'priv-good',
          displayName: 'Good Group',
          nameStatus: 'decrypted',
        }),
        expect.objectContaining({
          groupId: 'priv-bad',
          displayName: null,
          nameStatus: 'unreadable',
        }),
      ]),
    )
    expect(results).toHaveLength(2)
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

  it('does not cache a failed decrypt, so the next call retries it instead of staying unreadable forever', async () => {
    // PR #144 review: caching a null result would mean a group that failed
    // once (transient, or fixed server-side at the same generation) never
    // gets retried for the rest of the tab session.
    const cache = fakeCache()
    const firstDecrypt = vi
      .fn()
      .mockResolvedValue([{ groupId: 'priv-1', name: null, description: null }])
    const firstDeps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup()] }),
      decryptGroupNames: firstDecrypt,
      getCachedGroupName: cache.getCachedGroupName,
      setCachedGroupName: cache.setCachedGroupName,
    })

    const firstResults = await runListGroups(firstDeps)
    expect(firstResults).toEqual([
      expect.objectContaining({ groupId: 'priv-1', displayName: null, nameStatus: 'unreadable' }),
    ])
    expect(cache.setCachedGroupName).not.toHaveBeenCalled()

    // A second call reusing the same cache must NOT hit a cached failure --
    // it must call decryptGroupNames again, same as a cold cache would.
    const secondDecrypt = vi
      .fn()
      .mockResolvedValue([{ groupId: 'priv-1', name: 'Fixed Now', description: 'Fixed' }])
    const secondDeps = makeDeps({
      listGroups: vi.fn().mockResolvedValue({ groups: [privateGroup()] }),
      decryptGroupNames: secondDecrypt,
      getCachedGroupName: cache.getCachedGroupName,
      setCachedGroupName: cache.setCachedGroupName,
    })

    const secondResults = await runListGroups(secondDeps)
    expect(secondDecrypt).toHaveBeenCalledTimes(1)
    expect(secondResults).toEqual([
      expect.objectContaining({ displayName: 'Fixed Now', nameStatus: 'decrypted' }),
    ])
  })

  // PR #144 review non-blocking #5: GET /api/groups reads GSI1, which is
  // eventually consistent on real DynamoDB. A group just created and
  // immediately navigated to can be transiently missing from the very next
  // fetch -- these pin the merge that covers it (newGroup, passed through
  // router state by CreateGroupScreen).
  describe('newGroup merge (GSI1 eventual-consistency mitigation)', () => {
    it('merges in newGroup when the fetched list does not include it yet', async () => {
      const newGroup = publicGroup({ groupId: 'brand-new', namePlaintext: 'Brand New Group' })
      const deps = makeDeps({
        listGroups: vi.fn().mockResolvedValue({ groups: [publicGroup({ groupId: 'existing' })] }),
        newGroup,
      })

      const results = await runListGroups(deps)

      // Order-independent -- the merge happens before sortByLabel runs, so
      // final position depends on alphabetical order, not merge order
      // (sortByLabel's own tests cover ordering specifically).
      expect(results.map((g) => g.groupId).sort()).toEqual(['brand-new', 'existing'])
      expect(results).toContainEqual(
        expect.objectContaining({ groupId: 'brand-new', displayName: 'Brand New Group' }),
      )
    })

    it('does not duplicate newGroup once the fetched list actually includes it', async () => {
      const newGroup = publicGroup({ groupId: 'now-present', namePlaintext: 'Now Present' })
      const deps = makeDeps({
        // The server has already caught up -- the fetched list includes
        // the group for real, with its actual (possibly different) data.
        listGroups: vi.fn().mockResolvedValue({
          groups: [publicGroup({ groupId: 'now-present', namePlaintext: 'Server Copy' })],
        }),
        newGroup,
      })

      const results = await runListGroups(deps)

      expect(results).toHaveLength(1)
      expect(results[0]?.displayName).toBe('Server Copy')
    })

    it('decrypts a merged-in private newGroup exactly like a fetched one', async () => {
      const newGroup = privateGroup({ groupId: 'brand-new-private' })
      const decryptGroupNames = vi
        .fn()
        .mockResolvedValue([
          { groupId: 'brand-new-private', name: 'New Private Group', description: 'Fresh' },
        ])
      const deps = makeDeps({
        listGroups: vi.fn().mockResolvedValue({ groups: [] }),
        decryptGroupNames,
        newGroup,
      })

      const results = await runListGroups(deps)

      expect(results).toEqual([
        expect.objectContaining({
          groupId: 'brand-new-private',
          displayName: 'New Private Group',
          nameStatus: 'decrypted',
        }),
      ])
    })

    it('does nothing when newGroup is undefined (the ordinary case)', async () => {
      const deps = makeDeps({
        listGroups: vi.fn().mockResolvedValue({ groups: [publicGroup()] }),
      })

      const results = await runListGroups(deps)

      expect(results).toHaveLength(1)
    })
  })

  // PR #144 review non-blocking #6: the server's own order (GSI1SK, i.e.
  // random gid) means nothing to a user -- sorting by what's actually
  // rendered reads better and is stable across reloads (unlike gid order,
  // which is also effectively random from a user's perspective).
  describe('sorting', () => {
    it('sorts public groups alphabetically by name, case-insensitively', async () => {
      const deps = makeDeps({
        listGroups: vi.fn().mockResolvedValue({
          groups: [
            publicGroup({ groupId: 'z', namePlaintext: 'zebra group' }),
            publicGroup({ groupId: 'a', namePlaintext: 'Apple Group' }),
            publicGroup({ groupId: 'm', namePlaintext: 'mango group' }),
          ],
        }),
      })

      const results = await runListGroups(deps)

      expect(results.map((g) => g.groupId)).toEqual(['a', 'm', 'z'])
    })

    it('sorts a fallback label (unreadable/coldKeys) into its own alphabetical position, not always first or last', async () => {
      const deps = makeDeps({
        listGroups: vi.fn().mockResolvedValue({
          groups: [
            publicGroup({ groupId: 'z-named', namePlaintext: 'Zephyr Group' }),
            publicGroup({ groupId: 'a-named', namePlaintext: 'Apple Group' }),
            privateGroup({ groupId: 'cold' }), // no cache, no decrypt call configured below -> stays coldKeys
          ],
        }),
        decryptGroupNames: vi.fn().mockRejectedValue(new Error('worker: no live keys cached')),
      })

      const results = await runListGroups(deps)

      // groupLabel('coldKeys') is "(private group)" -- "(" sorts before
      // any letter in locale order, so it lands first here. The point of
      // this test is that it sorts BY that label like any other entry,
      // not that it's pinned to a fixed position by nameStatus.
      expect(results.map((g) => g.groupId)).toEqual(['cold', 'a-named', 'z-named'])
    })
  })
})
