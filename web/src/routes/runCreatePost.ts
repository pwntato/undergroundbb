// The async bodies behind CreatePostScreen -- #42. Plain functions that take
// their network and worker calls as arguments, the split runGroupSettings.ts
// makes, so they are unit-testable with no jsdom or real worker.
//
// Two steps, so a lost response can be resent byte for byte: prepare loads the
// group and seals the post, send posts it. The server accepts the same bytes
// twice as one post, so an ambiguous failure is answered by sending the same
// sealed post again, never by sealing a second one.

import { ApiError } from '@/lib/api/auth'
import type { CreatePostRequest, GroupDetail } from '@/lib/api/groups'
import { utf8Length } from '@/lib/crypto/post'
import type { SealedPost } from '@/lib/crypto/worker-protocol'
import { isLiveKeysError } from './runListGroups'

export interface PostLimits {
  readonly maxTitleBytes: number
  readonly maxBodyBytes: number
}

/** The server's defaults (internal/config), used only when GET /api/config cannot be read. */
export const DEFAULT_POST_LIMITS: PostLimits = { maxTitleBytes: 200, maxBodyBytes: 10000 }

export type PostFormProblem = 'titleEmpty' | 'titleTooLong' | 'bodyTooLong'

/** What is wrong with the form, or null. The title is required; the body may be empty. */
export function validatePostForm(
  title: string,
  body: string,
  limits: PostLimits,
): PostFormProblem | null {
  if (title.trim() === '') {
    return 'titleEmpty'
  }
  if (utf8Length(title) > limits.maxTitleBytes) {
    return 'titleTooLong'
  }
  if (utf8Length(body) > limits.maxBodyBytes) {
    return 'bodyTooLong'
  }
  return null
}

export const FORM_PROBLEMS: Record<PostFormProblem, string> = {
  titleEmpty: 'Give the post a title.',
  titleTooLong: 'The title is too long.',
  bodyTooLong: 'The post is too long.',
}

export interface PrepareDeps {
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  readonly getChain: (
    groupId: string,
    fromGeneration: number,
    toGeneration: number,
  ) => Promise<
    | readonly {
        readonly generation: number
        readonly wrapped: { nonce: string; ciphertext: string }
      }[]
    | undefined
  >
  readonly sealPost: (req: {
    readonly userId: string
    readonly groupId: string
    readonly generation: number
    readonly postGeneration: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly chain?: readonly {
      readonly generation: number
      readonly wrapped: { nonce: string; ciphertext: string }
    }[]
    readonly title: string
    readonly body: string
  }) => Promise<SealedPost>
  readonly userId: string
}

export type PrepareResult =
  | { readonly ok: true; readonly sealed: SealedPost }
  | {
      readonly ok: false
      readonly kind:
        'invalid' | 'notFound' | 'authRequired' | 'coldKeys' | 'behind' | 'unreadable' | 'failed'
      readonly problem?: PostFormProblem
    }

/** Loads the group, works out which generation new posts use, and seals the post. Never throws. */
export async function preparePost(
  deps: PrepareDeps,
  groupId: string,
  title: string,
  body: string,
  limits: PostLimits,
): Promise<PrepareResult> {
  const problem = validatePostForm(title, body, limits)
  if (problem !== null) {
    return { ok: false, kind: 'invalid', problem }
  }
  let detail: GroupDetail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return { ok: false, kind: 'notFound' }
    }
    if (err instanceof ApiError && err.status === 401) {
      return { ok: false, kind: 'authRequired' }
    }
    return { ok: false, kind: 'failed' }
  }
  if (detail.role === '' || detail.wrappedGroupKey === undefined) {
    return { ok: false, kind: 'notFound' }
  }
  // While a rotation runs, new posts stay on the generation being rotated away
  // from (docs/DESIGN.md); a member already moved up opens that key through the
  // chain. Otherwise they use the group's current one.
  const postGeneration =
    detail.rotation !== undefined ? detail.rotation.generation - 1 : detail.generation
  if (detail.generation < postGeneration) {
    return { ok: false, kind: 'behind' }
  }
  let chain: Awaited<ReturnType<PrepareDeps['getChain']>> = []
  if (detail.generation > postGeneration) {
    chain = await deps.getChain(groupId, postGeneration, detail.generation)
    if (chain === undefined) {
      return { ok: false, kind: 'unreadable' }
    }
  }
  try {
    const sealed = await deps.sealPost({
      userId: deps.userId,
      groupId,
      generation: detail.generation,
      postGeneration,
      wrappedGroupKey: detail.wrappedGroupKey,
      ...(chain !== undefined && chain.length > 0 && { chain }),
      title,
      body,
    })
    return { ok: true, sealed }
  } catch (err) {
    if (isLiveKeysError(err)) {
      return { ok: false, kind: 'coldKeys' }
    }
    return { ok: false, kind: 'unreadable' }
  }
}

export interface SendDeps {
  readonly createPost: (groupId: string, req: CreatePostRequest) => Promise<{ sortKey: string }>
}

export type SendResult =
  | { readonly ok: true }
  | {
      readonly ok: false
      readonly kind:
        // Seal again from a fresh load: the group's key, the member's entry or the keys moved.
        | 'reseal'
        | 'behind'
        | 'dormant'
        | 'authRequired'
        | 'notFound'
        | 'rejected'
        // No answer: the post may or may not have landed. Send the same bytes again.
        | 'ambiguous'
      readonly message?: string
    }

/** Posts a sealed post. Never throws. */
export async function sendPost(
  deps: SendDeps,
  groupId: string,
  sealed: SealedPost,
): Promise<SendResult> {
  try {
    await deps.createPost(groupId, {
      sortKey: sealed.sortKey,
      generation: sealed.generation,
      nonce: sealed.nonce,
      ciphertext: sealed.ciphertext,
      signature: sealed.signature,
    })
    return { ok: true }
  } catch (err) {
    if (!(err instanceof ApiError) || err.status >= 500) {
      return { ok: false, kind: 'ambiguous' }
    }
    if (err.status === 401) {
      return { ok: false, kind: 'authRequired' }
    }
    if (err.status === 404) {
      return { ok: false, kind: 'notFound' }
    }
    switch (err.code) {
      case 'generation_stale':
      case 'membership_changed':
      case 'key_epoch_stale':
      case 'post_exists':
      case 'conflict_retry':
        return { ok: false, kind: 'reseal' }
      case 'member_behind':
        return { ok: false, kind: 'behind' }
      case 'member_dormant':
        return { ok: false, kind: 'dormant' }
    }
    return { ok: false, kind: 'rejected', message: err.message }
  }
}
