// The async bodies behind the reply box -- #44, docs/DESIGN.md "Comments (#44)".
// Plain functions over injected deps, like runCreatePost.ts, so they are
// unit-testable with no DOM or worker.
//
// The CLIENT picks a comment's path (the signature and the AAD cover it), so
// two members replying to the same comment can pick the same number. The server
// answers 409 `comment_path_taken` or `comment_path_skips` with `nextPath`, and
// the answer is to seal again at that path -- a different comment, so a retry
// here is a new seal, never a resend. A resend (same bytes) is only for an
// answer that never came: the server accepts identical bytes twice as one
// comment, so an ambiguous failure is answered by sending the same sealed
// comment again.

import { ApiError } from '@/lib/api/auth'
import { CommentPathError, type CreateCommentRequest } from '@/lib/api/groups'
import { utf8Length } from '@/lib/crypto/post'
import type { SealedComment } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'
import { loadPostingKey, type PrepareDeps } from './runCreatePost'
import { commentDepth } from './runLoadThread'

/** The server's default (internal/config), used only when GET /api/config cannot be read. */
export const DEFAULT_MAX_COMMENT_BYTES = 10000

/** Replies stop at this depth; a reply to a comment at it is written beside it. */
export const MAX_COMMENT_DEPTH = 8
const MAX_ORDINAL = 9999

/** Seals at most this many times for one send (the first guess plus corrections). */
export const MAX_PATH_ATTEMPTS = 4

export type CommentProblem = 'empty' | 'tooLong'

/** What is wrong with the text, or null. Text that is only whitespace is empty. */
export function validateComment(text: string, maxBytes: number): CommentProblem | null {
  if (text.trim() === '') return 'empty'
  if (utf8Length(text) > maxBytes) return 'tooLong'
  return null
}

export const COMMENT_PROBLEMS: Record<CommentProblem, string> = {
  empty: 'Write something first.',
  tooLong: 'The comment is too long.',
}

/** The path of a comment's parent; '' for a top-level comment. */
export function parentPath(path: string): string {
  const i = path.lastIndexOf('.')
  return i < 0 ? '' : path.slice(0, i)
}

/**
 * The path a reply to `target` (null: a new top-level comment) is written under:
 * the target itself, or at the depth cap its parent, so the reply sits beside it.
 */
export function attachParent(target: string | null): string {
  if (target === null) return ''
  return commentDepth(target) >= MAX_COMMENT_DEPTH ? parentPath(target) : target
}

/** Whether a reply to `target` is written beside it instead of under it. */
export function attachesBeside(target: string): boolean {
  return commentDepth(target) >= MAX_COMMENT_DEPTH
}

/**
 * The next free path under `parent` as far as the loaded comments show: one past
 * the highest direct child seen. A thread is read in pages, so this can be wrong
 * (a later page holds more children); the server corrects it with `nextPath`.
 */
export function guessPath(parent: string, loaded: Iterable<string>): string {
  let highest = 0
  for (const path of loaded) {
    if (commentDepth(path) === 0 || parentPath(path) !== parent) continue
    highest = Math.max(highest, Number(path.slice(path.lastIndexOf('.') + 1)))
  }
  const segment = String(Math.min(highest + 1, MAX_ORDINAL)).padStart(4, '0')
  return parent === '' ? segment : `${parent}.${segment}`
}

/** What sealing a comment needs besides the path and text. */
export interface SealContext {
  readonly generation: number
  readonly commentGeneration: number
  readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
  readonly chain?: readonly {
    readonly generation: number
    readonly wrapped: { nonce: string; ciphertext: string }
  }[]
}

export interface ContextDeps {
  readonly getGroup: PrepareDeps['getGroup']
  readonly getChain: PrepareDeps['getChain']
}

export type ContextResult =
  | { readonly ok: true; readonly context: SealContext }
  | {
      readonly ok: false
      readonly kind: 'notFound' | 'authRequired' | 'behind' | 'unreadable' | 'failed'
    }

/** Loads the group and works out which generation new comments use. Never throws. */
export async function loadSealContext(deps: ContextDeps, groupId: string): Promise<ContextResult> {
  const key = await loadPostingKey(deps, groupId)
  if (!key.ok) return key
  return {
    ok: true,
    context: {
      generation: key.generation,
      commentGeneration: key.postGeneration,
      wrappedGroupKey: key.wrappedGroupKey,
      ...(key.chain !== undefined && { chain: key.chain }),
    },
  }
}

export interface SubmitDeps {
  readonly userId: string
  readonly sealComment: (req: {
    readonly userId: string
    readonly groupId: string
    readonly postId: string
    readonly path: string
    readonly generation: number
    readonly commentGeneration: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: NonNullable<SealContext['chain']>
    readonly text: string
  }) => Promise<SealedComment>
  readonly createComment: (postId: string, req: CreateCommentRequest) => Promise<{ path: string }>
}

export type SubmitResult =
  | { readonly ok: true; readonly path: string }
  | {
      readonly ok: false
      readonly kind:
        // The group's key, the member's entry or the keys moved: load the context and seal again.
        | 'reseal'
        | 'behind'
        | 'dormant'
        | 'authRequired'
        | 'notFound'
        | 'coldKeys'
        | 'unreadable'
        // This comment has as many replies as can be numbered.
        | 'repliesFull'
        // The comment being replied to was deleted.
        | 'parentGone'
        // Other writers kept taking the number; the retries ran out.
        | 'busy'
        | 'rejected'
        // No answer, or a conflict with a send still in flight: the comment may
        // or may not have landed. `sealed` is sent again unchanged.
        | 'ambiguous'
      readonly message?: string
      /** The comment to send again; set only for 'ambiguous'. */
      readonly sealed?: SealedComment
    }

/**
 * Seals a comment at `firstPath` and sends it, sealing again at the server's
 * `nextPath` when the path was not the next free one, at most MAX_PATH_ATTEMPTS
 * times. With `resend` (a comment a send left unanswered) the first attempt
 * sends those exact bytes instead of sealing. Never throws.
 */
export async function submitComment(
  deps: SubmitDeps,
  input: {
    readonly groupId: string
    readonly postId: string
    readonly context: SealContext
    readonly text: string
    readonly firstPath: string
    readonly resend?: SealedComment
  },
): Promise<SubmitResult> {
  const parent = parentPath(input.firstPath)
  const tried = new Set<string>()
  let path = input.firstPath
  let pending = input.resend
  for (let attempt = 0; attempt < MAX_PATH_ATTEMPTS; attempt++) {
    let sealed: SealedComment
    if (pending !== undefined) {
      sealed = pending
      path = sealed.path
      pending = undefined
    } else {
      try {
        sealed = await deps.sealComment({
          userId: deps.userId,
          groupId: input.groupId,
          postId: input.postId,
          path,
          generation: input.context.generation,
          commentGeneration: input.context.commentGeneration,
          wrappedGroupKey: input.context.wrappedGroupKey,
          ...(input.context.chain !== undefined && { chain: input.context.chain }),
          text: input.text,
        })
      } catch (err) {
        return { ok: false, kind: isLiveKeysError(err) ? 'coldKeys' : 'unreadable' }
      }
    }
    tried.add(path)
    try {
      await deps.createComment(input.postId, {
        path: sealed.path,
        generation: sealed.generation,
        signedDay: sealed.signedDay,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        signature: sealed.signature,
      })
      return { ok: true, path: sealed.path }
    } catch (err) {
      if (err instanceof CommentPathError) {
        // Believe the server only as far as the shape: a path under the same
        // parent that has not been tried. Anything else would loop or misplace.
        const next = err.nextPath
        if (commentDepth(next) === 0 || parentPath(next) !== parent || tried.has(next)) {
          return { ok: false, kind: 'rejected', message: err.message }
        }
        path = next
        continue
      }
      return { ...failure(err), ...(isAmbiguous(err) && { sealed }) }
    }
  }
  return { ok: false, kind: 'busy' }
}

function isAmbiguous(err: unknown): boolean {
  if (!(err instanceof ApiError) || err.status >= 500) return true
  return err.status === 409 && err.code === 'conflict_retry'
}

function failure(err: unknown): Extract<SubmitResult, { ok: false }> {
  if (isAmbiguous(err)) return { ok: false, kind: 'ambiguous' }
  const e = err as ApiError
  if (e.status === 401) return { ok: false, kind: 'authRequired' }
  if (e.status === 404) return { ok: false, kind: 'notFound' }
  switch (e.code) {
    case 'generation_stale':
    case 'membership_changed':
    case 'key_epoch_stale':
      return { ok: false, kind: 'reseal' }
    case 'member_behind':
      return { ok: false, kind: 'behind' }
    case 'member_dormant':
      return { ok: false, kind: 'dormant' }
    case 'replies_full':
      return { ok: false, kind: 'repliesFull' }
    case 'parent_gone':
      return { ok: false, kind: 'parentGone' }
  }
  return { ok: false, kind: 'rejected', message: e.message }
}
