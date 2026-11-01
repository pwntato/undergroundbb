// The async bodies behind Edit and Delete on a comment -- #45, docs/DESIGN.md
// "Editing and deleting a comment". Plain functions over injected deps, like
// runCreateComment.ts, so they are unit-testable with no DOM or worker.
//
// An edit is sealed again at the SAME path under the generation new comments use,
// with a fresh nonce, the comment's original time and the edit time (worker op
// sealCommentEdit). What each answer means is in runEdit.ts, which runs the loop.

import type { EditCommentRequest } from '@/lib/api/groups'
import type { SealedComment } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'
import { loadSealContext, type ContextDeps, type SealContext } from './runCreateComment'
import { runEdit, type EditResult } from './runEdit'

export {
  classifyEditError,
  MAX_EDIT_RESEALS,
  MAX_EDIT_RETRIES,
  type EditFailure,
  type EditResult,
} from './runEdit'

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

/** The edit of `path` sealed and sent; see runEdit.ts. Never throws. */
export function submitCommentEdit(
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
): Promise<EditResult<SealedComment>> {
  return runEdit<SealedComment>({
    goneCode: 'comment_gone',
    resend: input.resend,
    seal: async () => {
      const loaded = await loadSealContext(deps.context, input.groupId)
      if (!loaded.ok) return { ok: false, kind: loaded.kind }
      try {
        const sealed = await deps.sealCommentEdit({
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
        return { ok: true, sealed }
      } catch (err) {
        return { ok: false, kind: isLiveKeysError(err) ? 'coldKeys' : 'unreadable' }
      }
    },
    send: (sealed) =>
      deps.editComment(input.postId, input.path, {
        generation: sealed.generation,
        signedDay: sealed.signedDay,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        signature: sealed.signature,
      }),
  })
}
