// The async body behind the thread screen -- #44, docs/DESIGN.md "Comments
// (#44)". A plain function over injected deps, like runListPosts.ts, whose
// author anchoring it shares: one call loads one page of a post's comments,
// opens each under the key of ITS generation, and checks each signature under
// the author's keys for the day the author signed.
//
// What a reader trusts, and what it does not (the same rules as a post):
//   - A comment opens under commentAAD, which binds the post, the path and the
//     generation, or it is `unreadable`. The nonce is not signed, so that says
//     nothing about the author.
//   - The signature covers the author, group, `CMT#<path>`, generation, signed
//     day and ciphertext, NOT the post: the post is bound by the AAD alone. A
//     failed read of the author's keys is 'unchecked', never 'invalid'.
//   - The decrypted `at` is whatever the author signed: a comment whose time is
//     not on its signed day is flagged `timeSuspect`.
//   - A path that is not a well-formed path cannot be placed in the thread, so
//     it is shown as unreadable with a failed signature check and is never
//     indented.
//
// Order: the server pages in display order (depth first, by path), and this keeps
// it. A page can end between a comment and its replies, and an empty page can
// carry a cursor; both mean "keep going", never "the end".

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, ThreadResponse, WireComment, WireReaction } from '@/lib/api/groups'
import { checkCommentSignature, atOnSignedDay } from '@/lib/crypto/comment-check'
import { groupOfPostId } from '@/lib/crypto/post-check'
import type { OpenedComment, OpenedReaction } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'
import type { AuthorCheck, ListPostsDeps, PostSignature } from './runListPosts'

export interface LoadThreadDeps {
  readonly getGroup: ListPostsDeps['getGroup']
  readonly getChain: ListPostsDeps['getChain']
  readonly getThread: (postId: string, cursor?: string) => Promise<ThreadResponse>
  readonly openComments: (req: {
    readonly userId: string
    readonly groupId: string
    readonly postId: string
    readonly generation: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: readonly {
      readonly generation: number
      readonly wrapped: { nonce: string; ciphertext: string }
    }[]
    readonly comments: readonly {
      readonly path: string
      readonly generation: number
      readonly nonce: string
      readonly ciphertext: string
    }[]
  }) => Promise<readonly OpenedComment[]>
  readonly openReactions: (req: {
    readonly userId: string
    readonly groupId: string
    readonly postId: string
    readonly generation: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: readonly {
      readonly generation: number
      readonly wrapped: { nonce: string; ciphertext: string }
    }[]
    readonly reactions: readonly {
      readonly target: string
      readonly reactorUserId: string
      readonly generation: number
      readonly nonce: string
      readonly ciphertext: string
    }[]
  }) => Promise<readonly OpenedReaction[]>
  readonly selfUserId: string
}

/** The target of a reaction on the post itself. */
export const POST_TARGET = '0000'

/**
 * One reaction as shown: who, on what, and which table index (reaction.ts), or
 * null when it did not open or holds a byte this build has no reaction for.
 * Unsigned, so nothing here vouches for the reactor beyond the server's word.
 */
export interface ReactionView {
  /** The comment path it is on, or POST_TARGET. */
  readonly target: string
  readonly reactorUserId: string
  readonly index: number | null
}

export interface CommentView {
  /** `0003.0001`; the key of the comment within its post. */
  readonly path: string
  /** How many segments the path has (1 for a top-level comment); 0 if the path is malformed. */
  readonly depth: number
  readonly authorUserId: string
  /** Null for a deleted account or an author whose profile could not be read. */
  readonly authorName: string | null
  /** The UTC day the author signed. */
  readonly signedDay: string
  readonly content:
    | {
        readonly kind: 'opened'
        readonly text: string
        readonly at: string
        /** The decrypted time is not on the signed day. */
        readonly timeSuspect: boolean
      }
    | { readonly kind: 'unreadable' }
  readonly signature: PostSignature
  /** How the author's keys were anchored; absent when they were not (see signature). */
  readonly keyAnchor?: 'own' | 'pinned' | 'first-seen'
}

export type ThreadPageResult =
  | {
      readonly ok: true
      readonly comments: readonly CommentView[]
      /** The page's reactions: the post's own on the first page, then those on this page's comments. */
      readonly reactions: readonly ReactionView[]
      readonly nextCursor?: string
    }
  | {
      readonly ok: false
      readonly kind: 'notFound' | 'authRequired' | 'coldKeys' | 'chain' | 'failed'
    }

const PATH = /^\d{4}(\.\d{4}){0,7}$/

/** Segments in a well-formed comment path (no segment 0000), or 0 for anything else. */
export function commentDepth(path: string): number {
  if (!PATH.test(path)) return 0
  const segments = path.split('.')
  return segments.some((s) => s === '0000') ? 0 : segments.length
}

/** Loads, opens and checks one page of a post's thread. Never throws. */
export async function loadThreadPage(
  deps: LoadThreadDeps,
  resolveAuthor: (userId: string) => Promise<AuthorCheck>,
  groupId: string,
  postId: string,
  cursor?: string,
): Promise<ThreadPageResult> {
  // The group comes from one URL parameter and the post from another, and the
  // server authorizes the post against ITS group, so a mismatched pair would
  // read another group's comments under this group's key.
  if (groupOfPostId(postId) !== groupId) return { ok: false, kind: 'notFound' }
  let detail: GroupDetail
  let page: ThreadResponse
  try {
    ;[detail, page] = await Promise.all([deps.getGroup(groupId), deps.getThread(postId, cursor)])
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return { ok: false, kind: 'notFound' }
    if (err instanceof ApiError && err.status === 401) return { ok: false, kind: 'authRequired' }
    return { ok: false, kind: 'failed' }
  }
  if (detail.role === '' || detail.wrappedGroupKey === undefined) {
    return { ok: false, kind: 'notFound' }
  }
  const nextCursor =
    page.nextCursor !== undefined && page.nextCursor !== ''
      ? { nextCursor: page.nextCursor }
      : undefined
  const wire = page.comments
  // A reaction on a target that is neither the post nor a well-formed comment path
  // cannot be placed anywhere, so it is not opened or shown.
  const wireReactions = page.reactions.filter(
    (x) => x.target === POST_TARGET || commentDepth(x.target) > 0,
  )
  // The first page can hold only the post's own reactions, so an empty page of
  // comments is not an empty page.
  if (wire.length === 0 && wireReactions.length === 0) {
    return { ok: true, comments: [], reactions: [], ...nextCursor }
  }

  const oldest = Math.min(
    ...wire.map((c) => c.generation),
    ...wireReactions.map((x) => x.generation),
  )
  let chain: Awaited<ReturnType<LoadThreadDeps['getChain']>> = []
  if (oldest < detail.generation) {
    chain = await deps.getChain(groupId, oldest, detail.generation)
    // A failed read of the chain is not a comment that does not open.
    if (chain === undefined) return { ok: false, kind: 'chain' }
  }
  const keyed = {
    userId: deps.selfUserId,
    groupId,
    postId,
    generation: detail.generation,
    wrappedGroupKey: detail.wrappedGroupKey,
    ...(chain.length > 0 && { chain }),
  }
  let opened: readonly OpenedComment[] = []
  if (wire.length > 0) {
    try {
      opened = await deps.openComments({
        ...keyed,
        comments: wire.map((c) => ({
          path: c.path,
          generation: c.generation,
          nonce: c.nonce,
          ciphertext: c.ciphertext,
        })),
      })
    } catch (err) {
      return { ok: false, kind: isLiveKeysError(err) ? 'coldKeys' : 'failed' }
    }
  }
  // A reaction that cannot be opened is not worth losing the comments over: a
  // cold tab still asks for the password, anything else shows them unreadable.
  let openedReactions: readonly OpenedReaction[] = []
  if (wireReactions.length > 0) {
    try {
      openedReactions = await deps.openReactions({
        ...keyed,
        reactions: wireReactions.map((x) => ({
          target: x.target,
          reactorUserId: x.reactorUserId,
          generation: x.generation,
          nonce: x.nonce,
          ciphertext: x.ciphertext,
        })),
      })
    } catch (err) {
      if (isLiveKeysError(err)) return { ok: false, kind: 'coldKeys' }
    }
  }
  const authors = new Map(
    await Promise.all(
      [...new Set(wire.map((c) => c.authorUserId))].map(
        async (id) => [id, await resolveAuthor(id)] as const,
      ),
    ),
  )
  return {
    ok: true,
    comments: wire.map((c, i) =>
      viewOf(c, opened[i] ?? { kind: 'unreadable' }, authors.get(c.authorUserId)!, groupId),
    ),
    reactions: wireReactions.map((x, i) => reactionViewOf(x, openedReactions[i])),
    ...nextCursor,
  }
}

function reactionViewOf(x: WireReaction, o: OpenedReaction | undefined): ReactionView {
  return {
    target: x.target,
    reactorUserId: x.reactorUserId,
    index: o?.kind === 'opened' ? o.index : null,
  }
}

function viewOf(
  c: WireComment,
  o: OpenedComment,
  author: AuthorCheck,
  groupId: string,
): CommentView {
  const depth = commentDepth(c.path)
  const wellFormed = depth > 0
  const signature: PostSignature = !wellFormed
    ? { kind: 'invalid' }
    : author.kind === 'unchecked'
      ? { kind: 'unchecked', reason: author.reason }
      : checkCommentSignature({
          groupId,
          authorUserId: c.authorUserId,
          path: c.path,
          generation: c.generation,
          signedDay: c.signedDay,
          ciphertext: c.ciphertext,
          signature: c.signature,
          author: author.keys,
        })
  return {
    path: c.path,
    depth,
    authorUserId: c.authorUserId,
    authorName: author.username,
    signedDay: c.signedDay,
    content:
      o.kind === 'opened' && wellFormed
        ? {
            kind: 'opened',
            text: o.text,
            at: o.at,
            timeSuspect: !atOnSignedDay(c.signedDay, o.at),
          }
        : { kind: 'unreadable' },
    signature,
    ...(author.kind === 'keys' && { keyAnchor: author.anchor }),
  }
}
