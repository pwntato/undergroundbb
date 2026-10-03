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
import { nameStamp } from '@/lib/groups/groupNameCache'
import { groupLabel } from './groupLabel'

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
  /**
   * A group CreateGroupScreen just created, passed through router state
   * (newGroupNavigationState.ts) -- merged into the fetched list if
   * GET /api/groups doesn't already include it, since that read goes
   * through GSI1, which is eventually consistent (PR #144 review): a group
   * created and then immediately navigated to can be transiently missing
   * from the very next fetch on real DynamoDB. Undefined on every ordinary
   * visit to Home (a plain reload, or navigating here some other way) --
   * only CreateGroupScreen's own navigate() call ever sets this.
   */
  readonly newGroup?: GroupListEntry
  readonly decryptGroupNames: (req: {
    readonly userId: string
    readonly groups: readonly {
      readonly groupId: string
      readonly generation: number
      readonly nameGeneration: number
      readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
      readonly nameCiphertext: { nonce: string; ciphertext: string }
      readonly descriptionCiphertext: { nonce: string; ciphertext: string }
      readonly chain?: readonly {
        readonly generation: number
        readonly wrapped: { nonce: string; ciphertext: string }
      }[]
    }[]
  }) => Promise<readonly DecryptedGroupName[]>
  /**
   * Fetches the GENKEY# links a group's name needs when it was sealed under an
   * older generation than the member's own (fetchNameChain). Optional only so a
   * caller with no network can skip the walk; such a group reads as unreadable.
   */
  readonly getNameChain?: (
    groupId: string,
    nameGeneration: number,
    generation: number,
  ) => Promise<
    | readonly {
        readonly generation: number
        readonly wrapped: { nonce: string; ciphertext: string }
      }[]
    | undefined
  >
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
    stamp: string,
  ) => { name: string | null; description: string | null } | null
  readonly setCachedGroupName: (
    userId: string,
    groupId: string,
    generation: number,
    stamp: string,
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
 * The chain links a group's name needs, as a spread-able field: nothing when
 * the name is at the member's own generation, and also nothing when the fetch
 * failed (the decrypt then reports the name unreadable, uncached, so a later
 * load retries).
 */
async function chainFor(
  deps: Pick<ListGroupsDeps, 'getNameChain'>,
  group: GroupListEntry,
): Promise<{
  chain?: NonNullable<Awaited<ReturnType<NonNullable<ListGroupsDeps['getNameChain']>>>>
}> {
  if (deps.getNameChain === undefined || group.nameGeneration >= group.generation) {
    return {}
  }
  const chain = await deps.getNameChain(group.groupId, group.nameGeneration, group.generation)
  return chain === undefined ? {} : { chain }
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
  const { groups: fetched } = await deps.listGroups()

  // Merge in a just-created group the fetched list doesn't have yet (GSI1
  // eventual consistency, this function's own header comment) -- appended
  // rather than prepended, so a freshly created group doesn't jump ahead of
  // an existing one in whatever order the server returned; ordering is a
  // separate concern (PR #144 review non-blocking #6) this merge doesn't
  // need to solve.
  const groups =
    deps.newGroup && !fetched.some((g) => g.groupId === deps.newGroup?.groupId)
      ? [...fetched, deps.newGroup]
      : fetched

  const results: DisplayGroup[] = []
  const toDecrypt: {
    groupId: string
    generation: number
    nameGeneration: number
    wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    nameCiphertext: { nonce: string; ciphertext: string }
    descriptionCiphertext: { nonce: string; ciphertext: string }
    chain?: readonly { generation: number; wrapped: { nonce: string; ciphertext: string } }[]
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

    const stamp = nameStamp(group.nameCiphertext, group.descriptionCiphertext)
    const cached = deps.getCachedGroupName(deps.userId, group.groupId, group.nameGeneration, stamp)
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
      ...(await chainFor(deps, group)),
      groupId: group.groupId,
      generation: group.generation,
      nameGeneration: group.nameGeneration,
      wrappedGroupKey: group.wrappedGroupKey,
      nameCiphertext: group.nameCiphertext,
      descriptionCiphertext: group.descriptionCiphertext,
    })
  }

  if (toDecrypt.length === 0) {
    return sortByLabel(results)
  }

  let decrypted: readonly DecryptedGroupName[]
  try {
    decrypted = await deps.decryptGroupNames({ userId: deps.userId, groups: toDecrypt })
  } catch (err) {
    if (isLiveKeysError(err)) {
      // Every pending entry stays 'coldKeys' -- already the initial value
      // set above, so there is nothing further to do here.
      return sortByLabel(results)
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
    // Only cache a SUCCESSFUL decrypt (PR #144 review) -- caching a failure
    // too would mean a group that failed once (a transient issue, or a
    // server-side data fix at the same generation) stays 'unreadable' for
    // the rest of the tab session, never retried. The cost of not caching a
    // failure is one extra worker call per bad group on the next load,
    // which is cheap next to getting stuck permanently wrong.
    if (result.name !== null) {
      deps.setCachedGroupName(
        deps.userId,
        result.groupId,
        group.nameGeneration,
        stampOf(group),
        result.name,
        result.description,
      )
    }
  }

  return sortByLabel(results)
}

// sortByLabel orders the final list by what the user actually sees
// (groupLabel's own rendered text) -- PR #144 review non-blocking #6: the
// unsorted order is GSI1SK order, i.e. by random gid, which is stable but
// means nothing to a user. Sorting by the same string groupLabel produces
// (rather than raw displayName) means an unreadable/coldKeys entry's own
// fallback label sorts predictably by its own text too, instead of by a
// null displayName that would need its own special-casing here. A locale-
// aware compare (not <) handles case and diacritics the way a user expects
// alphabetical order to work.
function sortByLabel(groups: DisplayGroup[]): DisplayGroup[] {
  return [...groups].sort((a, b) => groupLabel(a).localeCompare(groupLabel(b)))
}

// The stamp of the ciphertext a fetched group entry carries. Only called for
// entries that reached the decrypt step, which by construction have both.
function stampOf(group: GroupListEntry): string {
  if (!group.nameCiphertext || !group.descriptionCiphertext) {
    return ''
  }
  return nameStamp(group.nameCiphertext, group.descriptionCiphertext)
}
