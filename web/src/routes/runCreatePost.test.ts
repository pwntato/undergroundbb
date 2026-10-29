import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { SealedPost } from '@/lib/crypto/worker-protocol'
import {
  DEFAULT_POST_LIMITS,
  preparePost,
  sendPost,
  validatePostForm,
  type PrepareDeps,
} from './runCreatePost'

const LIMITS = { maxTitleBytes: 10, maxBodyBytes: 20 }
const WRAPPED = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }
const SEALED: SealedPost = {
  sortKey: 'POST#2026-10-28#00112233445566ff',
  generation: 0,
  nonce: 'n',
  ciphertext: 'c',
  signature: 's',
}

function detail(over: Record<string, unknown> = {}): GroupDetail {
  return {
    groupId: 'g',
    role: 'member',
    generation: 0,
    wrappedGroupKey: WRAPPED,
    ...over,
  } as unknown as GroupDetail
}

function deps(over: Partial<PrepareDeps> = {}): PrepareDeps & {
  sealPost: ReturnType<typeof vi.fn>
  getChain: ReturnType<typeof vi.fn>
} {
  return {
    getGroup: vi.fn().mockResolvedValue(detail()),
    getChain: vi.fn().mockResolvedValue([]),
    sealPost: vi.fn().mockResolvedValue(SEALED),
    userId: 'u1',
    ...over,
  } as never
}

describe('validatePostForm', () => {
  it('requires a title and counts bytes, not characters', () => {
    expect(validatePostForm('', 'x', LIMITS)).toBe('titleEmpty')
    expect(validatePostForm('   ', 'x', LIMITS)).toBe('titleEmpty')
    expect(validatePostForm('a'.repeat(10), '', LIMITS)).toBeNull()
    expect(validatePostForm('a'.repeat(11), '', LIMITS)).toBe('titleTooLong')
    // Five characters, ten bytes: at the cap. Six is over it.
    expect(validatePostForm('é'.repeat(5), '', LIMITS)).toBeNull()
    expect(validatePostForm('é'.repeat(6), '', LIMITS)).toBe('titleTooLong')
    expect(validatePostForm('t', 'b'.repeat(20), LIMITS)).toBeNull()
    expect(validatePostForm('t', 'b'.repeat(21), LIMITS)).toBe('bodyTooLong')
    expect(validatePostForm('t', '日'.repeat(7), LIMITS)).toBe('bodyTooLong')
  })

  it('matches the server defaults', () => {
    expect(DEFAULT_POST_LIMITS).toEqual({ maxTitleBytes: 200, maxBodyBytes: 10000 })
  })
})

describe('preparePost', () => {
  it('seals at the group generation with no chain', async () => {
    const d = deps()
    expect(await preparePost(d, 'g', 'Hi', 'There', LIMITS)).toEqual({ ok: true, sealed: SEALED })
    expect(d.sealPost).toHaveBeenCalledWith({
      userId: 'u1',
      groupId: 'g',
      generation: 0,
      postGeneration: 0,
      wrappedGroupKey: WRAPPED,
      title: 'Hi',
      body: 'There',
    })
    expect(d.getChain).not.toHaveBeenCalled()
  })

  it('does not load or seal anything for an invalid form', async () => {
    const d = deps()
    expect(await preparePost(d, 'g', '', 'x', LIMITS)).toEqual({
      ok: false,
      kind: 'invalid',
      problem: 'titleEmpty',
    })
    expect(d.getGroup).not.toHaveBeenCalled()
    expect(d.sealPost).not.toHaveBeenCalled()
  })

  it('stays one generation behind a running rotation, walking the chain when moved up', async () => {
    const chain = [{ generation: 0, wrapped: { nonce: 'n', ciphertext: 'c' } }]
    const d = deps({
      getGroup: vi.fn().mockResolvedValue(detail({ generation: 1, rotation: { generation: 1 } })),
      getChain: vi.fn().mockResolvedValue(chain),
    })
    expect((await preparePost(d, 'g', 't', 'b', LIMITS)).ok).toBe(true)
    expect(d.getChain).toHaveBeenCalledWith('g', 0, 1)
    expect(d.sealPost.mock.calls[0]?.[0]).toMatchObject({ generation: 1, postGeneration: 0, chain })
  })

  it('does not post to a rotation it is not part of yet at the old generation', async () => {
    // Still at 0 while rotating to 1: new posts use 0, which is the member's own.
    const d = deps({
      getGroup: vi.fn().mockResolvedValue(detail({ generation: 0, rotation: { generation: 1 } })),
    })
    await preparePost(d, 'g', 't', 'b', LIMITS)
    expect(d.sealPost.mock.calls[0]?.[0]).toMatchObject({ generation: 0, postGeneration: 0 })
    expect(d.getChain).not.toHaveBeenCalled()
  })

  it('stops when the chain cannot be fetched', async () => {
    const d = deps({
      getGroup: vi.fn().mockResolvedValue(detail({ generation: 1, rotation: { generation: 1 } })),
      getChain: vi.fn().mockResolvedValue(undefined),
    })
    expect(await preparePost(d, 'g', 't', 'b', LIMITS)).toEqual({ ok: false, kind: 'unreadable' })
    expect(d.sealPost).not.toHaveBeenCalled()
  })

  it('reports a member behind the generation new posts use', async () => {
    // A marker rotating to 2 means new posts use generation 1; this entry is at 0.
    const d = deps({
      getGroup: vi.fn().mockResolvedValue(detail({ generation: 0, rotation: { generation: 2 } })),
    })
    expect(await preparePost(d, 'g', 't', 'b', LIMITS)).toEqual({ ok: false, kind: 'behind' })
    expect(d.sealPost).not.toHaveBeenCalled()
  })

  it('maps load failures', async () => {
    const fail = (err: unknown) => deps({ getGroup: vi.fn().mockRejectedValue(err) })
    expect(await preparePost(fail(new ApiError(404, 'x')), 'g', 't', 'b', LIMITS)).toEqual({
      ok: false,
      kind: 'notFound',
    })
    expect(await preparePost(fail(new ApiError(401, 'x')), 'g', 't', 'b', LIMITS)).toEqual({
      ok: false,
      kind: 'authRequired',
    })
    expect(await preparePost(fail(new ApiError(500, 'x')), 'g', 't', 'b', LIMITS)).toEqual({
      ok: false,
      kind: 'failed',
    })
    expect(await preparePost(fail(new TypeError('offline')), 'g', 't', 'b', LIMITS)).toEqual({
      ok: false,
      kind: 'failed',
    })
  })

  it('treats a non-member view or a missing wrapped key as not found', async () => {
    for (const over of [{ role: '' }, { wrappedGroupKey: undefined }]) {
      const d = deps({ getGroup: vi.fn().mockResolvedValue(detail(over)) })
      expect(await preparePost(d, 'g', 't', 'b', LIMITS)).toEqual({ ok: false, kind: 'notFound' })
    }
  })

  it('maps worker failures: cold keys are recoverable, anything else is unreadable', async () => {
    const cold = deps({
      sealPost: vi.fn().mockRejectedValue(new Error('worker: no live keys cached -- log in again')),
    })
    expect(await preparePost(cold, 'g', 't', 'b', LIMITS)).toEqual({ ok: false, kind: 'coldKeys' })
    const bad = deps({
      sealPost: vi.fn().mockRejectedValue(new Error('crypto: wrap did not open')),
    })
    expect(await preparePost(bad, 'g', 't', 'b', LIMITS)).toEqual({ ok: false, kind: 'unreadable' })
  })
})

describe('sendPost', () => {
  const send = (err: unknown) =>
    sendPost({ createPost: vi.fn().mockRejectedValue(err) }, 'g', SEALED)

  it('sends exactly the sealed fields', async () => {
    const createPost = vi.fn().mockResolvedValue({ sortKey: SEALED.sortKey })
    expect(await sendPost({ createPost }, 'g', SEALED)).toEqual({ ok: true })
    expect(createPost).toHaveBeenCalledWith('g', SEALED)
  })

  it('reseals when the group, the entry or the keys moved', async () => {
    for (const code of [
      'generation_stale',
      'membership_changed',
      'key_epoch_stale',
      'post_exists',
      'conflict_retry',
    ]) {
      expect(await send(new ApiError(409, 'x', code))).toEqual({ ok: false, kind: 'reseal' })
    }
  })

  it('names a member who is behind or dormant', async () => {
    expect(await send(new ApiError(409, 'x', 'member_behind'))).toEqual({
      ok: false,
      kind: 'behind',
    })
    expect(await send(new ApiError(409, 'x', 'member_dormant'))).toEqual({
      ok: false,
      kind: 'dormant',
    })
  })

  it('maps session and membership loss', async () => {
    expect(await send(new ApiError(401, 'x'))).toEqual({ ok: false, kind: 'authRequired' })
    expect(await send(new ApiError(404, 'x'))).toEqual({ ok: false, kind: 'notFound' })
  })

  it('shows the server message for any other refusal', async () => {
    expect(await send(new ApiError(400, 'ciphertext: too long', 'x'))).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'ciphertext: too long',
    })
    expect(await send(new ApiError(400, 'signature: bad', 'bad_signature'))).toMatchObject({
      kind: 'rejected',
    })
  })

  it('is ambiguous when no answer came, so the same bytes can be sent again', async () => {
    expect(await send(new TypeError('offline'))).toEqual({ ok: false, kind: 'ambiguous' })
    expect(await send(new ApiError(502, 'bad gateway'))).toEqual({ ok: false, kind: 'ambiguous' })
    expect(await send(new ApiError(500, 'oops'))).toEqual({ ok: false, kind: 'ambiguous' })
  })
})
