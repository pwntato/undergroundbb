// The async body behind Edit on a post -- #45, docs/DESIGN.md "Editing and
// deleting a post". A plain function over injected deps, like runEditComment.ts.
// The edit is sealed again under the same sort key and the generation new posts
// use, with a fresh nonce, the post's original time and the edit time (worker op
// sealPostEdit, which signs over the later of today and the filing day). What
// each answer means is in runEdit.ts, which runs the loop.

import type { EditPostRequest } from '@/lib/api/groups'
import type { SealedPostEdit } from '@/lib/crypto/worker-protocol'
import { loadPostingKey, type PrepareDeps } from './runCreatePost'
import { runEdit, type EditResult } from './runEdit'
import { isLiveKeysError } from './runListGroups'

export interface EditPostDeps {
  readonly userId: string
  readonly getGroup: PrepareDeps['getGroup']
  readonly getChain: PrepareDeps['getChain']
  readonly sealPostEdit: (req: {
    readonly userId: string
    readonly groupId: string
    readonly sortKey: string
    readonly generation: number
    readonly postGeneration: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: NonNullable<
      Extract<Awaited<ReturnType<typeof loadPostingKey>>, { ok: true }>['chain']
    >
    readonly title: string
    readonly body: string
    readonly at: string
  }) => Promise<SealedPostEdit>
  readonly editPost: (postId: string, req: EditPostRequest) => Promise<{ sortKey: string }>
}

/** The edit of the post sealed and sent; see runEdit.ts. Never throws. */
export function submitPostEdit(
  deps: EditPostDeps,
  input: {
    readonly groupId: string
    readonly postId: string
    readonly sortKey: string
    readonly title: string
    readonly body: string
    /** The post's original write time, kept by the edit. */
    readonly at: string
    readonly resend?: SealedPostEdit
  },
): Promise<EditResult<SealedPostEdit>> {
  return runEdit<SealedPostEdit>({
    goneCode: 'post_gone',
    resend: input.resend,
    seal: async () => {
      const key = await loadPostingKey(deps, input.groupId)
      if (!key.ok) return { ok: false, kind: key.kind }
      try {
        const sealed = await deps.sealPostEdit({
          userId: deps.userId,
          groupId: input.groupId,
          sortKey: input.sortKey,
          generation: key.generation,
          postGeneration: key.postGeneration,
          wrappedGroupKey: key.wrappedGroupKey,
          ...(key.chain !== undefined && { chain: key.chain }),
          title: input.title,
          body: input.body,
          at: input.at,
        })
        return { ok: true, sealed }
      } catch (err) {
        return { ok: false, kind: isLiveKeysError(err) ? 'coldKeys' : 'unreadable' }
      }
    },
    send: (sealed) =>
      deps.editPost(input.postId, {
        generation: sealed.generation,
        signedDay: sealed.signedDay,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
        signature: sealed.signature,
      }),
  })
}
