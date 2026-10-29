// The async body behind the post list -- #43, docs/DESIGN.md "For the reader".
// A plain function over injected deps, like runCreatePost.ts. One call loads one
// page: the group (for the caller's key), the GENKEY# links back to the oldest
// post on the page, the page itself, and each distinct author's keys.
//
// What a reader trusts, and what it does not:
//   - A post opens under the key of ITS generation, or it is `unreadable`. The
//     nonce is not signed, so that says nothing about the author.
//   - The signature is checked under the author's signing keys for the sort
//     key's day (lib/crypto/post-check). Those keys are what the server serves,
//     so they are anchored first, the same rule as the roster's grant check:
//     your own key from the worker; anyone else's against your signed pin. A
//     matching pin is 'pinned'; no pin yet is trusted on first use, saved, and
//     shown as 'first-seen'; a pin that mismatches, rolled back or does not
//     verify is never re-pinned over, and the post is 'unchecked' with the
//     reason. A failed read is 'unchecked', never 'invalid'.
//   - The decrypted `at` is whatever the author signed: a post whose time is not
//     on the sort key's day is flagged `timeSuspect`.
//
// Order: the server pages newest sort key first, which is newest day first and
// random within a day, so each page is re-sorted within each day by the decrypted
// time, newest first, unreadable posts last. A day that runs over a page boundary
// is ordered within each page only.

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, ListPostsResponse, WirePost } from '@/lib/api/groups'
import type { UserDetail } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import type { OwnKeyHistory } from '@/lib/crypto/own-history'
import { evaluatePin, servedSigningKeySet, type PinRecord } from '@/lib/crypto/pin'
import {
  atOnSortKeyDay,
  checkPostSignature,
  sortKeyDay,
  type AuthorKeys,
} from '@/lib/crypto/post-check'
import type { OpenedPost } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'

export interface ListPostsDeps {
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  /** The GENKEY# links for generations `from`..`to`-1; undefined when they could not be read. */
  readonly getChain: (
    groupId: string,
    from: number,
    to: number,
  ) => Promise<
    readonly { generation: number; wrapped: { nonce: string; ciphertext: string } }[] | undefined
  >
  readonly listPosts: (groupId: string, cursor?: string) => Promise<ListPostsResponse>
  readonly openPosts: (req: {
    readonly userId: string
    readonly groupId: string
    readonly generation: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: readonly {
      readonly generation: number
      readonly wrapped: { nonce: string; ciphertext: string }
    }[]
    readonly posts: readonly {
      readonly sortKey: string
      readonly generation: number
      readonly nonce: string
      readonly ciphertext: string
    }[]
  }) => Promise<readonly OpenedPost[]>
  readonly getUserDetail: (userId: string) => Promise<UserDetail>
  readonly selfUserId: string
  /** The caller's own CURRENT signing public key (base64), from the worker. */
  readonly ownSigningKey: () => Promise<string>
  readonly loadOwnKeyHistory?: (ownSigningKey: Uint8Array) => Promise<OwnKeyHistory | null>
  readonly listPins: () => Promise<readonly PinRecord[]>
  /** Signs and stores a pin (base64 keys). Rejects if it could not be saved. */
  readonly pinKeys: (
    pinnedUserId: string,
    signingPublicKeys: readonly string[],
    wrappingPublicKey: string,
    keyEpoch: number,
  ) => Promise<void>
}

/** How an author's keys were anchored before their signature was checked. */
export type KeyAnchor = 'own' | 'pinned' | 'first-seen'

export type AuthorCheck =
  | {
      readonly kind: 'keys'
      readonly keys: AuthorKeys
      readonly anchor: KeyAnchor
      readonly username: string | null
    }
  | { readonly kind: 'unchecked'; readonly reason: string; readonly username: string | null }

export type PostSignature =
  | { readonly kind: 'valid' }
  | { readonly kind: 'invalid' }
  | { readonly kind: 'unchecked'; readonly reason: string }

export interface PostView {
  readonly sortKey: string
  /** The UTC day in the sort key. */
  readonly day: string
  readonly authorUserId: string
  /** Null for a deleted account or an author whose profile could not be read. */
  readonly authorName: string | null
  readonly content:
    | {
        readonly kind: 'opened'
        readonly title: string
        readonly body: string
        readonly at: string
        /** The decrypted time is not on the sort key's day. */
        readonly timeSuspect: boolean
      }
    | { readonly kind: 'unreadable' }
  readonly signature: PostSignature
  /** How the author's keys were anchored; absent when they were not (see signature). */
  readonly keyAnchor?: KeyAnchor
}

export type PageResult =
  | { readonly ok: true; readonly posts: readonly PostView[]; readonly nextCursor?: string }
  | {
      readonly ok: false
      readonly kind: 'notFound' | 'authRequired' | 'coldKeys' | 'chain' | 'failed'
    }

/**
 * Resolves each author's anchored keys once and remembers the answer for the
 * life of the resolver (one screen visit), so a long list reads each author a
 * single time. The pins and the caller's own key are read lazily, on the first
 * author who is not the caller.
 */
export function makeAuthorResolver(deps: ListPostsDeps): (userId: string) => Promise<AuthorCheck> {
  const cache = new Map<string, Promise<AuthorCheck>>()
  let ground:
    | Promise<{
        own: Uint8Array
        pins: Map<string, PinRecord>
        history: OwnKeyHistory | undefined
      }>
    | undefined
  const readGround = () => {
    ground ??= (async () => {
      const own = base64ToBytes(await deps.ownSigningKey())
      const pins = new Map((await deps.listPins()).map((p) => [p.pinnedUserId, p]))
      const history = (await deps.loadOwnKeyHistory?.(own)) ?? undefined
      return { own, pins, history }
    })()
    return ground
  }

  async function resolve(userId: string): Promise<AuthorCheck> {
    let served: UserDetail
    try {
      served = await deps.getUserDetail(userId)
    } catch {
      return { kind: 'unchecked', reason: 'their keys could not be read', username: null }
    }
    const username = served.username === '' ? null : served.username
    const keys: AuthorKeys = {
      signingPublicKey: served.signingPublicKey,
      keyChanges: served.keyChanges,
    }
    let g: Awaited<ReturnType<typeof readGround>>
    try {
      g = await readGround()
    } catch {
      return {
        kind: 'unchecked',
        reason: 'your own keys or saved keys could not be read',
        username,
      }
    }
    if (userId === deps.selfUserId) {
      return sameKey(served.signingPublicKey, g.own)
        ? { kind: 'keys', keys, anchor: 'own', username }
        : {
            kind: 'unchecked',
            reason: 'the keys served for you are not the ones you hold',
            username,
          }
    }
    const verdict = evaluatePin({
      pinnerUserId: deps.selfUserId,
      pinnerSigningPublicKey: g.own,
      pinnerHistory: g.history,
      pinnedUserId: userId,
      pin: g.pins.get(userId),
      served,
    })
    if (verdict === 'match') return { kind: 'keys', keys, anchor: 'pinned', username }
    if (verdict === 'first-sight') {
      const set = servedSigningKeySet(served)
      if (set === null) {
        return { kind: 'unchecked', reason: 'the keys served for them are malformed', username }
      }
      try {
        await deps.pinKeys(
          userId,
          set.map(bytesToBase64),
          served.wrappingPublicKey,
          served.keyEpoch,
        )
      } catch {
        return {
          kind: 'unchecked',
          reason: 'their keys could not be saved, so nothing vouches for them yet',
          username,
        }
      }
      return { kind: 'keys', keys, anchor: 'first-seen', username }
    }
    return { kind: 'unchecked', reason: unanchoredReason(verdict), username }
  }

  return (userId) => {
    let found = cache.get(userId)
    if (found === undefined) {
      found = resolve(userId).catch((): AuthorCheck => ({
        kind: 'unchecked',
        reason: 'their keys could not be read',
        username: null,
      }))
      cache.set(userId, found)
    }
    return found
  }
}

function sameKey(b64: string, key: Uint8Array): boolean {
  try {
    const bytes = base64ToBytes(b64)
    return bytes.length === key.length && bytes.every((x, i) => x === key[i])
  } catch {
    return false
  }
}

function unanchoredReason(verdict: ReturnType<typeof evaluatePin>): string {
  switch (verdict) {
    case 'mismatch':
      return 'their keys changed since you saved them'
    case 'rollback':
      return 'the server shows older keys for them than you saw before'
    default:
      return 'the copy of their keys you saved does not verify'
  }
}

/** Loads, opens and checks one page of posts. Never throws. */
export async function loadPostsPage(
  deps: ListPostsDeps,
  resolveAuthor: (userId: string) => Promise<AuthorCheck>,
  groupId: string,
  cursor?: string,
): Promise<PageResult> {
  let detail: GroupDetail
  let page: ListPostsResponse
  try {
    ;[detail, page] = await Promise.all([deps.getGroup(groupId), deps.listPosts(groupId, cursor)])
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { ok: false, kind: 'notFound' }
    if (err instanceof ApiError && err.status === 401) return { ok: false, kind: 'authRequired' }
    return { ok: false, kind: 'failed' }
  }
  if (detail.role === '' || detail.wrappedGroupKey === undefined) {
    return { ok: false, kind: 'notFound' }
  }
  const posts = page.posts
  const attempt = await openAll(deps, detail, groupId, posts)
  if (!attempt.ok) return attempt
  const opened = attempt.opened
  const authors = await Promise.all(
    [...new Set(posts.map((p) => p.authorUserId))].map(
      async (id) => [id, await resolveAuthor(id)] as const,
    ),
  )
  const byAuthor = new Map(authors)
  const views = posts.map((p, i) => viewOf(p, opened[i]!, byAuthor.get(p.authorUserId)!, groupId))
  return {
    ok: true,
    posts: orderWithinDays(views),
    ...(page.nextCursor !== undefined && page.nextCursor !== '' && { nextCursor: page.nextCursor }),
  }
}

async function openAll(
  deps: ListPostsDeps,
  detail: GroupDetail,
  groupId: string,
  posts: readonly WirePost[],
): Promise<
  { readonly ok: true; readonly opened: readonly OpenedPost[] } | Extract<PageResult, { ok: false }>
> {
  if (posts.length === 0) return { ok: true, opened: [] }
  const oldest = Math.min(...posts.map((p) => p.generation))
  let chain: Awaited<ReturnType<ListPostsDeps['getChain']>> = []
  if (oldest < detail.generation) {
    chain = await deps.getChain(groupId, oldest, detail.generation)
    // A failed read of the chain is not a post that does not open.
    if (chain === undefined) return { ok: false, kind: 'chain' }
  }
  try {
    const opened = await deps.openPosts({
      userId: deps.selfUserId,
      groupId,
      generation: detail.generation,
      wrappedGroupKey: detail.wrappedGroupKey!,
      ...(chain.length > 0 && { chain }),
      posts: posts.map((p) => ({
        sortKey: p.sortKey,
        generation: p.generation,
        nonce: p.nonce,
        ciphertext: p.ciphertext,
      })),
    })
    return { ok: true, opened }
  } catch (err) {
    return { ok: false, kind: isLiveKeysError(err) ? 'coldKeys' : 'failed' }
  }
}

function viewOf(p: WirePost, o: OpenedPost, author: AuthorCheck, groupId: string): PostView {
  const day = sortKeyDay(p.sortKey) ?? ''
  const signature: PostSignature =
    author.kind === 'unchecked'
      ? { kind: 'unchecked', reason: author.reason }
      : checkPostSignature({
          groupId,
          authorUserId: p.authorUserId,
          sortKey: p.sortKey,
          generation: p.generation,
          ciphertext: p.ciphertext,
          signature: p.signature,
          author: author.keys,
        })
  return {
    sortKey: p.sortKey,
    day,
    authorUserId: p.authorUserId,
    authorName: author.username,
    content:
      o.kind === 'opened'
        ? {
            kind: 'opened',
            title: o.title,
            body: o.body,
            at: o.at,
            timeSuspect: !atOnSortKeyDay(p.sortKey, o.at),
          }
        : { kind: 'unreadable' },
    signature,
    ...(author.kind === 'keys' && { keyAnchor: author.anchor }),
  }
}

/** Keeps the server's day order; inside a day, opened posts newest time first, unreadable last. */
function orderWithinDays(views: readonly PostView[]): PostView[] {
  const days: PostView[][] = []
  for (const v of views) {
    const last = days[days.length - 1]
    if (last !== undefined && last[0]!.day === v.day) last.push(v)
    else days.push([v])
  }
  return days.flatMap((group) =>
    group
      .map((v, i) => ({ v, i }))
      .sort((a, b) => {
        const ca = a.v.content
        const cb = b.v.content
        if (ca.kind !== cb.kind) return ca.kind === 'opened' ? -1 : 1
        if (ca.kind === 'opened' && cb.kind === 'opened' && ca.at !== cb.at) {
          return ca.at < cb.at ? 1 : -1
        }
        return a.i - b.i
      })
      .map((x) => x.v),
  )
}
