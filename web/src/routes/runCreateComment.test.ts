import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { CommentPathError, type GroupDetail } from '@/lib/api/groups'
import type { SealedComment } from '@/lib/crypto/worker-protocol'
import {
  attachesBeside,
  attachParent,
  guessPath,
  loadSealContext,
  MAX_PATH_ATTEMPTS,
  parentPath,
  submitComment,
  validateComment,
  type SealContext,
  type SubmitDeps,
} from './runCreateComment'

const WRAPPED = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }
const CONTEXT: SealContext = { generation: 0, commentGeneration: 0, wrappedGroupKey: WRAPPED }
const POST = 'g#2026-10-29#00112233445566ff'

function sealedAt(path: string): SealedComment {
  return {
    path,
    generation: 0,
    signedDay: '2026-10-29',
    nonce: `n-${path}`,
    ciphertext: `c-${path}`,
    signature: `s-${path}`,
  }
}

function deps(over: Partial<SubmitDeps> = {}) {
  const sealComment = vi.fn((req: { path: string }) => Promise.resolve(sealedAt(req.path)))
  const createComment = vi.fn().mockResolvedValue({ path: 'ignored' })
  return { userId: 'u1', sealComment, createComment, ...over } as SubmitDeps & {
    sealComment: typeof sealComment
    createComment: ReturnType<typeof vi.fn>
  }
}

const input = (firstPath: string, extra: object = {}) => ({
  groupId: 'g',
  postId: POST,
  context: CONTEXT,
  text: 'hi',
  firstPath,
  ...extra,
})

describe('validateComment', () => {
  it('refuses empty or whitespace-only text and counts bytes, not characters', () => {
    expect(validateComment('', 10)).toBe('empty')
    expect(validateComment(' \n ', 10)).toBe('empty')
    expect(validateComment('a'.repeat(10), 10)).toBeNull()
    expect(validateComment('a'.repeat(11), 10)).toBe('tooLong')
    // Three characters, nine bytes.
    expect(validateComment('€€€', 8)).toBe('tooLong')
    expect(validateComment('€€€', 9)).toBeNull()
  })
})

describe('paths', () => {
  it('finds the parent of a path', () => {
    expect(parentPath('0003')).toBe('')
    expect(parentPath('0003.0001.0002')).toBe('0003.0001')
  })

  it('replies under the comment, or beside it at the depth cap', () => {
    const deep = ['0001', '0001', '0001', '0001', '0001', '0001', '0001', '0001'].join('.')
    expect(attachParent(null)).toBe('')
    expect(attachParent('0001.0002')).toBe('0001.0002')
    expect(attachParent(deep)).toBe(parentPath(deep))
    expect(attachesBeside(deep)).toBe(true)
    expect(attachesBeside(parentPath(deep))).toBe(false)
  })

  it('guesses one past the highest loaded child of the same parent only', () => {
    const loaded = ['0001', '0001.0001', '0001.0002', '0002', '0002.0009', '0010']
    expect(guessPath('', loaded)).toBe('0011')
    expect(guessPath('0001', loaded)).toBe('0001.0003')
    expect(guessPath('0002', loaded)).toBe('0002.0010')
    // Nothing loaded under it yet.
    expect(guessPath('0010', loaded)).toBe('0010.0001')
    expect(guessPath('', [])).toBe('0001')
  })

  it('ignores malformed paths and never guesses past 9999', () => {
    expect(guessPath('', ['junk', '0000', '0003'])).toBe('0004')
    expect(guessPath('', ['9999'])).toBe('9999')
  })
})

describe('submitComment', () => {
  it('seals at the first path and sends exactly what was sealed', async () => {
    const d = deps()
    const out = await submitComment(d, input('0001.0003'))
    expect(out).toEqual({ ok: true, path: '0001.0003' })
    expect(d.sealComment).toHaveBeenCalledTimes(1)
    expect(d.sealComment.mock.calls[0]![0]).toMatchObject({
      userId: 'u1',
      groupId: 'g',
      postId: POST,
      path: '0001.0003',
      text: 'hi',
    })
    expect(d.createComment).toHaveBeenCalledWith(POST, {
      path: '0001.0003',
      generation: 0,
      signedDay: '2026-10-29',
      nonce: 'n-0001.0003',
      ciphertext: 'c-0001.0003',
      signature: 's-0001.0003',
    })
  })

  it.each(['comment_path_taken', 'comment_path_skips'])(
    'seals again at the path the server names on %s',
    async (code) => {
      const d = deps()
      d.createComment
        .mockRejectedValueOnce(new CommentPathError('x', code, '0001.0004'))
        .mockResolvedValueOnce({ path: '0001.0004' })
      const out = await submitComment(d, input('0001.0002'))
      expect(out).toEqual({ ok: true, path: '0001.0004' })
      expect(d.sealComment.mock.calls.map((c) => (c[0] as { path: string }).path)).toEqual([
        '0001.0002',
        '0001.0004',
      ])
    },
  )

  it('gives up after MAX_PATH_ATTEMPTS seals and says others are replying', async () => {
    const d = deps()
    let n = 1
    d.createComment.mockImplementation(() => {
      n++
      return Promise.reject(new CommentPathError('x', 'comment_path_taken', `000${String(n)}`))
    })
    const out = await submitComment(d, input('0001'))
    expect(out).toEqual({ ok: false, kind: 'busy' })
    expect(d.sealComment).toHaveBeenCalledTimes(MAX_PATH_ATTEMPTS)
  })

  it('does not follow a nextPath it already tried, or one under another parent', async () => {
    const same = deps()
    same.createComment.mockRejectedValue(
      new CommentPathError('x', 'comment_path_taken', '0001.0002'),
    )
    expect(await submitComment(same, input('0001.0002'))).toMatchObject({
      ok: false,
      kind: 'rejected',
    })
    expect(same.sealComment).toHaveBeenCalledTimes(1)

    const other = deps()
    other.createComment.mockRejectedValue(new CommentPathError('x', 'comment_path_taken', '0002'))
    expect(await submitComment(other, input('0001.0002'))).toMatchObject({
      ok: false,
      kind: 'rejected',
    })
    const junk = deps()
    junk.createComment.mockRejectedValue(new CommentPathError('x', 'comment_path_taken', 'nope'))
    expect(await submitComment(junk, input('0001'))).toMatchObject({ ok: false, kind: 'rejected' })
    expect(other.sealComment).toHaveBeenCalledTimes(1)
    expect(junk.sealComment).toHaveBeenCalledTimes(1)
  })

  it('keeps the sealed comment on a lost response and sends the same bytes again', async () => {
    const d = deps()
    d.createComment.mockRejectedValueOnce(new TypeError('network down'))
    const first = await submitComment(d, input('0004'))
    expect(first).toEqual({ ok: false, kind: 'ambiguous', sealed: sealedAt('0004') })
    if (first.ok || first.sealed === undefined) throw new Error('unreachable')

    const second = await submitComment(d, input('0004', { resend: first.sealed }))
    expect(second).toEqual({ ok: true, path: '0004' })
    // Sealed once; the second send is the first's bytes.
    expect(d.sealComment).toHaveBeenCalledTimes(1)
    expect(d.createComment.mock.calls[1]![1]).toEqual(d.createComment.mock.calls[0]![1])
  })

  it('treats a 500 and conflict_retry as ambiguous', async () => {
    for (const err of [new ApiError(500, 'boom'), new ApiError(409, 'busy', 'conflict_retry')]) {
      const d = deps()
      d.createComment.mockRejectedValue(err)
      expect(await submitComment(d, input('0001'))).toMatchObject({
        ok: false,
        kind: 'ambiguous',
      })
    }
  })

  it('reseals a resent comment whose path someone else took, as a new comment', async () => {
    const d = deps()
    d.createComment
      .mockRejectedValueOnce(new CommentPathError('x', 'comment_path_taken', '0005'))
      .mockResolvedValueOnce({ path: '0005' })
    const out = await submitComment(d, input('0004', { resend: sealedAt('0004') }))
    expect(out).toEqual({ ok: true, path: '0005' })
    expect(d.sealComment).toHaveBeenCalledTimes(1)
    expect((d.sealComment.mock.calls[0]![0] as { path: string }).path).toBe('0005')
  })

  it('names replies_full and parent_gone separately', async () => {
    const full = deps()
    full.createComment.mockRejectedValue(new ApiError(409, 'full', 'replies_full'))
    expect(await submitComment(full, input('0001.9999'))).toEqual({
      ok: false,
      kind: 'repliesFull',
    })
    const gone = deps()
    gone.createComment.mockRejectedValue(new ApiError(409, 'gone', 'parent_gone'))
    expect(await submitComment(gone, input('0001.0001'))).toEqual({
      ok: false,
      kind: 'parentGone',
    })
  })

  it.each([
    ['generation_stale', 'reseal'],
    ['membership_changed', 'reseal'],
    ['key_epoch_stale', 'reseal'],
    ['member_behind', 'behind'],
    ['member_dormant', 'dormant'],
  ])('maps %s to %s', async (code, kind) => {
    const d = deps()
    d.createComment.mockRejectedValue(new ApiError(409, 'x', code))
    expect(await submitComment(d, input('0001'))).toEqual({ ok: false, kind })
  })

  it('maps 401, 404 and other 4xx', async () => {
    const cases: [ApiError, string][] = [
      [new ApiError(401, 'x'), 'authRequired'],
      [new ApiError(404, 'x'), 'notFound'],
      [new ApiError(400, 'bad text'), 'rejected'],
    ]
    for (const [err, kind] of cases) {
      const d = deps()
      d.createComment.mockRejectedValue(err)
      expect(await submitComment(d, input('0001'))).toMatchObject({ ok: false, kind })
    }
  })

  it('reports cold keys, and other seal failures, without sending', async () => {
    const cold = deps({
      sealComment: vi.fn().mockRejectedValue(new Error('no live keys cached')),
    })
    expect(await submitComment(cold, input('0001'))).toEqual({ ok: false, kind: 'coldKeys' })
    expect(cold.createComment).not.toHaveBeenCalled()
    const bad = deps({ sealComment: vi.fn().mockRejectedValue(new Error('bad wrap')) })
    expect(await submitComment(bad, input('0001'))).toEqual({ ok: false, kind: 'unreadable' })
  })
})

describe('loadSealContext', () => {
  function group(over: Record<string, unknown> = {}): GroupDetail {
    return {
      groupId: 'g',
      role: 'member',
      generation: 2,
      wrappedGroupKey: WRAPPED,
      ...over,
    } as never
  }

  it('uses the current generation outside a rotation', async () => {
    const out = await loadSealContext(
      { getGroup: vi.fn().mockResolvedValue(group()), getChain: vi.fn() },
      'g',
    )
    expect(out).toEqual({
      ok: true,
      context: { generation: 2, commentGeneration: 2, wrappedGroupKey: WRAPPED },
    })
  })

  it('stays one generation back during a rotation and fetches the chain', async () => {
    const chain = [{ generation: 1, wrapped: { nonce: 'n', ciphertext: 'c' } }]
    const getChain = vi.fn().mockResolvedValue(chain)
    const out = await loadSealContext(
      { getGroup: vi.fn().mockResolvedValue(group({ rotation: { generation: 2 } })), getChain },
      'g',
    )
    expect(out).toEqual({
      ok: true,
      context: { generation: 2, commentGeneration: 1, wrappedGroupKey: WRAPPED, chain },
    })
    expect(getChain).toHaveBeenCalledWith('g', 1, 2)
  })

  it('maps a missing group, a lost session and an unreadable chain', async () => {
    const run = (getGroup: () => Promise<GroupDetail>, getChain = vi.fn()) =>
      loadSealContext({ getGroup, getChain }, 'g')
    expect(await run(() => Promise.reject(new ApiError(404, 'x')))).toEqual({
      ok: false,
      kind: 'notFound',
    })
    expect(await run(() => Promise.reject(new ApiError(401, 'x')))).toEqual({
      ok: false,
      kind: 'authRequired',
    })
    expect(await run(() => Promise.reject(new Error('net')))).toEqual({
      ok: false,
      kind: 'failed',
    })
    expect(
      await run(
        () => Promise.resolve(group({ rotation: { generation: 2 } })),
        vi.fn().mockResolvedValue(undefined),
      ),
    ).toEqual({ ok: false, kind: 'unreadable' })
  })
})
