// The async bodies behind Edit and Delete on a comment -- #45, docs/DESIGN.md
// "Editing and deleting a comment". Plain functions over injected deps, like
// runCreateComment.ts, so they are unit-testable with no DOM or worker.
//
// An edit is sealed again at the SAME path under the generation new comments use,
// with a fresh nonce, the comment's original time and the edit time (worker op
// sealCommentEdit). What an answer means:
//
//   - `conflict_retry`: another write to the same comment got there first. The
//     edit has not landed, and the same bytes are sent again (the write is
//     conditional on the edition the server reads, so a retry sees the new one).
//   - no answer / 5xx: the edit may or may not have landed. The caller keeps
//     `sealed` and sends exactly those bytes next time; the server answers 200 for
//     bytes it already stores, even when the signing day has passed.
//   - `nonce_reused`, `generation_stale`, `membership_changed`, `key_epoch_stale`:
//     the bytes cannot be accepted as they are; load the context and seal again.
//   - `comment_gone`: someone deleted it meanwhile; nothing to retry.

import { ApiError } from '@/lib/api/auth'
import type { EditCommentRequest } from '@/lib/api/groups'
import type { SealedComment } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'
import { loadSealContext, type ContextDeps, type SealContext } from './runCreateComment'

/** Sends the same bytes again at most this many times after a write collision. */
export const MAX_EDIT_RETRIES = 3
/** Seals again at most this many times for one press. */
export const MAX_EDIT_RESEALS = 2

export interface EditDeps {
  readonly userId: string
  readonly context: ContextDeps
  readonly sealCommentEdit: (req: {
    readonly userId: string
    readonly groupId: string
    readonly postId: string
    readonly path: string
    readonly generation: number
    readonly commentGeneration: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: NonNullable<SealContext['chain']>
    readonly text: string
    readonly at: string
  }) => Promise<SealedComment>
  readonly editComment: (
    postId: string,
    path: string,
    req: EditCommentRequest,
  ) => Promise<{ path: string }>
}

export type EditFailure =
  | 'authRequired'
  /** The post or the group is gone for this member, e.g. the post was deleted. */
  | 'notFound'
  | 'behind'
  | 'dormant'
  | 'coldKeys'
  | 'unreadable'
  | 'failed'
  /** The comment was deleted while it was being edited. */
  | 'gone'
  /** Other writers kept colliding with this one, or the key kept moving. */
  | 'busy'
  | 'rejected'
  /** No answer: the edit may have landed. Send `sealed` again unchanged. */
  | 'ambiguous'

export type EditResult =
  | { readonly ok: true }
  | {
      readonly ok: false
      readonly kind: EditFailure
      readonly message?: string
      /** Set only for 'ambiguous'. */
      readonly sealed?: SealedComment
    }

type Step = 'retry' | 'reseal' | { readonly fail: EditFailure; readonly message?: string }

/** What an error from PUT .../comments/{path} means. */
export function classifyEditError(err: unknown): Step | 'ambiguous' {
  if (!(err instanceof ApiError) || err.status >= 500) return 'ambiguous'
  if (err.status === 401) return { fail: 'authRequired' }
  if (err.status === 404) return { fail: 'notFound' }
  if (err.status === 409) {
    switch (err.code) {
      case 'conflict_retry':
        return 'retry'
      case 'generation_stale':
      case 'membership_changed':
      case 'key_epoch_stale':
        return 'reseal'
      case 'comment_gone':
        return { fail: 'gone' }
      case 'member_behind':
        return { fail: 'behind' }
      case 'member_dormant':
        return { fail: 'dormant' }
    }
  }
  if (err.status === 400 && err.code === 'nonce_reused') return 'reseal'
  return { fail: 'rejected', message: err.message }
}

/**
 * Seals the edit of `path` and sends it, following the rules above. With
 * `resend` (an edit a send left unanswered) the first attempt sends those exact
 * bytes instead of sealing. Never throws.
 */
export async function submitCommentEdit(
  deps: EditDeps,
  input: {
    readonly groupId: string
    readonly postId: string
    readonly path: string
    readonly text: string
    /** The comment's original write time, kept by the edit. */
    readonly at: string
    readonly resend?: SealedComment
  },
): Promise<EditResult> {
  let pending = input.resend
  for (let reseals = 0; ; reseals++) {
    let sealed: SealedComment
    if (pending !== undefined) {
      sealed = pending
      pending = undefined
    } else {
      const loaded = await loadSealContext(deps.context, input.groupId)
      if (!loaded.ok) return { ok: false, kind: loaded.kind }
      try {
        sealed = await deps.sealCommentEdit({
          userId: deps.userId,
          groupId: input.groupId,
          postId: input.postId,
          path: input.path,
          generation: loaded.context.generation,
          commentGeneration: loaded.context.commentGeneration,
          wrappedGroupKey: loaded.context.wrappedGroupKey,
          ...(loaded.context.chain !== undefined && { chain: loaded.context.chain }),
          text: input.text,
          at: input.at,
        })
      } catch (err) {
        return { ok: false, kind: isLiveKeysError(err) ? 'coldKeys' : 'unreadable' }
      }
    }
    // The same bytes go again after a collision; only a new seal changes them.
    let step: Step = 'retry'
    for (let retries = 0; step === 'retry'; retries++) {
      try {
        await deps.editComment(input.postId, input.path, {
          generation: sealed.generation,
          signedDay: sealed.signedDay,
          nonce: sealed.nonce,
          ciphertext: sealed.ciphertext,
          signature: sealed.signature,
        })
        return { ok: true }
      } catch (err) {
        const next = classifyEditError(err)
        if (next === 'ambiguous') return { ok: false, kind: 'ambiguous', sealed }
        step = next
        if (step === 'retry' && retries >= MAX_EDIT_RETRIES) return { ok: false, kind: 'busy' }
      }
    }
    if (step !== 'reseal') {
      return {
        ok: false,
        kind: step.fail,
        ...(step.message !== undefined && { message: step.message }),
      }
    }
    if (reseals >= MAX_EDIT_RESEALS) return { ok: false, kind: 'busy' }
  }
}
