import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { SealedComment } from '@/lib/crypto/worker-protocol'
import {
  classifyEditError,
  MAX_EDIT_RESEALS,
  MAX_EDIT_RETRIES,
  submitCommentEdit,
  type EditDeps,
} from './runEditComment'

const WRAPPED = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }
const POST = 'g#2026-10-29#00112233445566ff'
const AT = '2026-10-29T10:00:00.000Z'

let counter = 0
const sealed = (): SealedComment => ({
  path: '0001.0002',
  generation: 3,
  signedDay: '2026-10-31',
  nonce: `n${String(++counter)}`,
  ciphertext: 'ct',
  signature: 'sig',
})

function setup(edit: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({ path: '0001.0002' })) {
  const sealCommentEdit = vi.fn().mockImplementation(() => Promise.resolve(sealed()))
  const getGroup = vi.fn().mockResolvedValue({
    groupId: 'g',
    role: 'member',
    generation: 3,
    wrappedGroupKey: WRAPPED,
  } as unknown as GroupDetail)
  const deps = {
    userId: 'u1',
    context: { getGroup, getChain: vi.fn() },
    sealCommentEdit,
    editComment: edit,
  } as unknown as EditDeps
  const run = (over: { resend?: SealedComment } = {}) =>
    submitCommentEdit(deps, {
      groupId: 'g',
      postId: POST,
      path: '0001.0002',
      text: 'new',
      at: AT,
      ...over,
    })
  return { run, sealCommentEdit, edit, getGroup }
}

const conflict = (code: string) => new ApiError(409, code, code)

describe('submitCommentEdit', () => {
  it('seals once at the same path with the original time and sends it', async () => {
    const s = setup()
    expect(await s.run()).toEqual({ ok: true })
    expect(s.sealCommentEdit).toHaveBeenCalledTimes(1)
    expect(s.sealCommentEdit.mock.calls[0]![0]).toMatchObject({
      userId: 'u1',
      groupId: 'g',
      postId: POST,
      path: '0001.0002',
      text: 'new',
      at: AT,
    })
    expect(s.edit).toHaveBeenCalledTimes(1)
    expect(s.edit.mock.calls[0]![0]).toBe(POST)
    expect(s.edit.mock.calls[0]![1]).toBe('0001.0002')
    expect(s.edit.mock.calls[0]![2]).toEqual({
      generation: 3,
      signedDay: '2026-10-31',
      nonce: 'n1',
      ciphertext: 'ct',
      signature: 'sig',
    })
  })

  it('sends the SAME bytes again after conflict_retry, without sealing again', async () => {
    const edit = vi.fn().mockRejectedValueOnce(conflict('conflict_retry'))
    edit.mockResolvedValue({ path: 'ok' })
    const s = setup(edit)
    expect(await s.run()).toEqual({ ok: true })
    expect(s.sealCommentEdit).toHaveBeenCalledTimes(1)
    expect(edit).toHaveBeenCalledTimes(2)
    expect(edit.mock.calls[1]![2]).toEqual(edit.mock.calls[0]![2])
  })

  it('gives up as busy when conflict_retry never clears, after MAX_EDIT_RETRIES resends', async () => {
    const s = setup(vi.fn().mockRejectedValue(conflict('conflict_retry')))
    expect(await s.run()).toEqual({ ok: false, kind: 'busy' })
    expect(s.edit).toHaveBeenCalledTimes(MAX_EDIT_RETRIES + 1)
    expect(s.sealCommentEdit).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['nonce_reused', 400],
    ['generation_stale', 409],
    ['membership_changed', 409],
    ['key_epoch_stale', 409],
  ])('loads the context and seals AGAIN on %s', async (code, status) => {
    const edit = vi.fn().mockRejectedValueOnce(new ApiError(status, code, code))
    edit.mockResolvedValue({ path: 'ok' })
    const s = setup(edit)
    expect(await s.run()).toEqual({ ok: true })
    expect(s.sealCommentEdit).toHaveBeenCalledTimes(2)
    expect(s.getGroup).toHaveBeenCalledTimes(2)
    // A new seal, so different bytes.
    expect(edit.mock.calls[1]![2].nonce).not.toBe(edit.mock.calls[0]![2].nonce)
  })

  it('stops as busy when the key keeps moving, after MAX_EDIT_RESEALS fresh seals', async () => {
    const s = setup(vi.fn().mockRejectedValue(conflict('generation_stale')))
    expect(await s.run()).toEqual({ ok: false, kind: 'busy' })
    expect(s.sealCommentEdit).toHaveBeenCalledTimes(MAX_EDIT_RESEALS + 1)
  })

  it('reports a comment that was deleted meanwhile, without retrying', async () => {
    const s = setup(vi.fn().mockRejectedValue(conflict('comment_gone')))
    expect(await s.run()).toEqual({ ok: false, kind: 'gone' })
    expect(s.edit).toHaveBeenCalledTimes(1)
  })

  it('keeps the sealed bytes when no answer came, so the next press resends them', async () => {
    const edit = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    edit.mockResolvedValue({ path: 'ok' })
    const s = setup(edit)
    const first = await s.run()
    expect(first).toMatchObject({ ok: false, kind: 'ambiguous' })
    const kept = (first as { sealed: SealedComment }).sealed
    expect(await s.run({ resend: kept })).toEqual({ ok: true })
    // Not sealed a second time, and exactly the bytes of the first send.
    expect(s.sealCommentEdit).toHaveBeenCalledTimes(1)
    expect(edit.mock.calls[1]![2]).toEqual(edit.mock.calls[0]![2])
  })

  it('treats a 5xx as no answer', async () => {
    const s = setup(vi.fn().mockRejectedValue(new ApiError(502, 'bad gateway')))
    expect(await s.run()).toMatchObject({ ok: false, kind: 'ambiguous' })
  })

  it('seals fresh when the resent bytes are refused as stale, rather than resending them forever', async () => {
    const edit = vi.fn().mockRejectedValueOnce(conflict('generation_stale'))
    edit.mockResolvedValue({ path: 'ok' })
    const s = setup(edit)
    expect(await s.run({ resend: sealed() })).toEqual({ ok: true })
    expect(s.sealCommentEdit).toHaveBeenCalledTimes(1)
  })

  it.each([
    [new ApiError(401, 'no'), 'authRequired'],
    [new ApiError(404, 'no'), 'notFound'],
    [conflict('member_behind'), 'behind'],
    [conflict('member_dormant'), 'dormant'],
  ])('maps %s to %s without retrying', async (err, kind) => {
    const s = setup(vi.fn().mockRejectedValue(err))
    expect(await s.run()).toEqual({ ok: false, kind })
    expect(s.edit).toHaveBeenCalledTimes(1)
  })

  it('passes the server message on for a rejection', async () => {
    const s = setup(
      vi.fn().mockRejectedValue(new ApiError(403, 'only the author can edit a comment')),
    )
    expect(await s.run()).toEqual({
      ok: false,
      kind: 'rejected',
      message: 'only the author can edit a comment',
    })
  })

  it('asks for the password when there are no live keys, and says unreadable for any other seal failure', async () => {
    const s = setup()
    s.sealCommentEdit.mockRejectedValueOnce(
      new Error('worker: no live keys cached -- log in again'),
    )
    expect(await s.run()).toEqual({ ok: false, kind: 'coldKeys' })
    s.sealCommentEdit.mockRejectedValueOnce(new Error('bad tag'))
    expect(await s.run()).toEqual({ ok: false, kind: 'unreadable' })
    expect(s.edit).not.toHaveBeenCalled()
  })

  it('reports a group that cannot be loaded without sealing or sending', async () => {
    const s = setup()
    s.getGroup.mockRejectedValue(new ApiError(404, 'no'))
    expect(await s.run()).toEqual({ ok: false, kind: 'notFound' })
    expect(s.sealCommentEdit).not.toHaveBeenCalled()
    expect(s.edit).not.toHaveBeenCalled()
  })
})

describe('classifyEditError', () => {
  it('treats anything that is not an API answer as no answer', () => {
    expect(classifyEditError(new TypeError('x'))).toBe('ambiguous')
  })
  it('does not retry a bare 400 or an unknown 409', () => {
    expect(classifyEditError(new ApiError(400, 'bad_signature', 'bad_signature'))).toMatchObject({
      fail: 'rejected',
    })
    expect(classifyEditError(conflict('something_new'))).toMatchObject({ fail: 'rejected' })
  })
})
