// The async body behind Home's group list -- pulled out to a plain function
// that takes its network/worker/cache calls as arguments, the same split
// runCreateGroup.ts/runSignup.ts make from their own screens, so this can be
// unit-tested directly without jsdom or a real worker/crypto worker.
//
// Unlike runCreateGroup, there is no ambiguous-failure/retry-caching
// concern here -- this is a pure read, not a write with a client-generated
// id that a lost response could silently duplicate. The one real
// complication is decryptGroupNames' own liveKeys dependency: a private
// group's name can only be decrypted while the worker's cached keys are
// live (populated by a completeLogin in this worker instance's lifetime),
// which a page reload resets. This function treats that as a per-group
// degradation, not a fatal error for the whole list -- see
// DisplayGroup.nameStatus's own doc comment.

import type { GroupListEntry, ListGroupsResponse } from '@/lib/api/groups'
import type { DecryptedGroupName } from '@/lib/crypto/worker-protocol'

/**
 * One group ready to render. For a public group, name/description are
 * always 'plaintext'. For a private group:
 * - 'decrypted': successfully read from cache or freshly decrypted.
 * - 'unreadable': liveKeys were live, but THIS group's own decrypt failed
 *   (stale cache from before a rotation this client hasn't caught up on,
 *   or genuinely corrupt data) -- see DecryptGroupNamesResponse's own doc
 *   comment on the protocol side.
 * - 'coldKeys': liveKeys were not live at all (e.g. this tab was reloaded
 *   since login) -- every private group in the list gets this status
 *   together, distinct from 'unreadable' (which is per-group) because a
 *   fresh login fixes every one of them at once, while an 'unreadable'
 *   entry would not be fixed by re-authenticating.
 */
export type DisplayGroup = GroupListEntry & {
  readonly displayName: string | null
  readonly displayDescription: string | null
  readonly nameStatus: 'plaintext' | 'decrypted' | 'unreadable' | 'coldKeys'
}

export interface ListGroupsDeps {
  readonly listGroups: () => Promise<ListGroupsResponse>
  readonly decryptGroupNames: (req: {
    readonly userId: string
    readonly groups: readonly {
      readonly groupId: string
      readonly generation: number
      readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
      readonly nameCiphertext: { nonce: string; ciphertext: string }
      readonly descriptionCiphertext: { nonce: string; ciphertext: string }
    }[]
  }) => Promise<readonly DecryptedGroupName[]>
  /**
   * groupNameCache.ts's getCachedGroupName/setCachedGroupName, injected
   * rather than imported directly -- this codebase's test suite runs under
   * vitest's `node` environment (vitest.config.ts), not jsdom (see
   * SignupProgressStep.test.tsx's own header comment on why:
   * renderToStaticMarkup is used instead), so there is no global
   * sessionStorage to test against directly. Injecting these as plain
   * functions, exactly like listGroups/decryptGroupNames above, is what
   * makes runListGroups.test.ts able to exercise the real cache-hit/miss
   * control flow with a simple in-memory fake instead.
   */
  readonly getCachedGroupName: (
    userId: string,
    groupId: string,
    generation: number,
  ) => { name: string | null; description: string | null } | null
  readonly setCachedGroupName: (
    userId: string,
    groupId: string,
    generation: number,
    name: string | null,
    description: string | null,
  ) => void
  readonly userId: string
}

/**
 * Reports whether err is worker.ts's decryptGroupNames throwing because
 * liveKeys is cold or belongs to a different account -- mirrors
 * CreateGroupScreen.tsx's own isLiveKeysError, matching the same two
 * substrings worker.ts's decryptGroupNames throws (see that function's own
 * doc comment).
 */
export function isLiveKeysError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message.includes('no live keys cached') ||
      error.message.includes('cached keys belong to a different account'))
  )
}

/**
 * Fetches the caller's group list and resolves every group to something
 * renderable: a public group's plaintext directly, a private group's name
 * from cache when the generation matches, and everything else in one
 * batched decryptGroupNames call. Never throws for a cold-keys or
 * per-group decrypt failure -- those become nameStatus values on the
 * affected entries instead, so Home can still render public groups (and
 * every field that needs no keys) even when every private group is
 * temporarily unreadable.
 */
export async function runListGroups(deps: ListGroupsDeps): Promise<DisplayGroup[]> {
  const { groups } = await deps.listGroups()

  const results: DisplayGroup[] = []
  const toDecrypt: {
    groupId: string
    generation: number
    wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    nameCiphertext: { nonce: string; ciphertext: string }
    descriptionCiphertext: { nonce: string; ciphertext: string }
  }[] = []
  // Index into `results` for each group still awaiting a decrypt, so the
  // decryptGroupNames response (or a cache hit) can be written back to the
  // right entry without a second pass keyed by id.
  const pendingIndexByGroupId = new Map<string, number>()

  for (const group of groups) {
    if (group.visibility === 'public') {
      results.push({
        ...group,
        displayName: group.namePlaintext ?? '',
        displayDescription: group.descriptionPlaintext ?? '',
        nameStatus: 'plaintext',
      })
      continue
    }

    // A private group always carries all three fields together
    // (groupListEntry's own doc comment on the Go side) -- if any is
    // missing, the response itself is malformed, which this function
    // cannot fix by decrypting; render it as unreadable rather than
    // throwing and blanking the rest of the list.
    if (!group.nameCiphertext || !group.descriptionCiphertext || !group.wrappedGroupKey) {
      results.push({
        ...group,
        displayName: null,
        displayDescription: null,
        nameStatus: 'unreadable',
      })
      continue
    }

    const cached = deps.getCachedGroupName(deps.userId, group.groupId, group.generation)
    if (cached) {
      results.push({
        ...group,
        displayName: cached.name,
        displayDescription: cached.description,
        nameStatus: cached.name === null ? 'unreadable' : 'decrypted',
      })
      continue
    }

    pendingIndexByGroupId.set(group.groupId, results.length)
    results.push({ ...group, displayName: null, displayDescription: null, nameStatus: 'coldKeys' })
    toDecrypt.push({
      groupId: group.groupId,
      generation: group.generation,
      wrappedGroupKey: group.wrappedGroupKey,
      nameCiphertext: group.nameCiphertext,
      descriptionCiphertext: group.descriptionCiphertext,
    })
  }

  if (toDecrypt.length === 0) {
    return results
  }

  let decrypted: readonly DecryptedGroupName[]
  try {
    decrypted = await deps.decryptGroupNames({ userId: deps.userId, groups: toDecrypt })
  } catch (err) {
    if (isLiveKeysError(err)) {
      // Every pending entry stays 'coldKeys' -- already the initial value
      // set above, so there is nothing further to do here.
      return results
    }
    throw err
  }

  for (const result of decrypted) {
    const index = pendingIndexByGroupId.get(result.groupId)
    if (index === undefined) {
      continue
    }
    const group = results[index]
    if (!group) {
      continue
    }
    results[index] = {
      ...group,
      displayName: result.name,
      displayDescription: result.description,
      nameStatus: result.name === null ? 'unreadable' : 'decrypted',
    }
    deps.setCachedGroupName(
      deps.userId,
      result.groupId,
      group.generation,
      result.name,
      result.description,
    )
  }

  return results
}
