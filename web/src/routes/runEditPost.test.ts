import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { SealedPostEdit } from '@/lib/crypto/worker-protocol'
import { classifyEditError, MAX_EDIT_RETRIES } from './runEdit'
import { submitPostEdit, type EditPostDeps } from './runEditPost'

const WRAPPED = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }
const SORT_KEY = 'POST#2026-10-29#00112233445566ff'
const POST = `g#${SORT_KEY.slice(5)}`
const AT = '2026-10-29T10:00:00.000Z'

let counter = 0
const sealed = (): SealedPostEdit => ({
  sortKey: SORT_KEY,
  generation: 3,
  signedDay: '2026-10-31',
  nonce: `n${String(++counter)}`,
  ciphertext: 'ct',
  signature: 'sig',
})

function setup(edit: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({ sortKey: SORT_KEY })) {
  const sealPostEdit = vi.fn().mockImplementation(() => Promise.resolve(sealed()))
  const getGroup = vi.fn().mockResolvedValue({
    groupId: 'g',
    role: 'member',
    generation: 3,
    wrappedGroupKey: WRAPPED,
  } as unknown as GroupDetail)
  const getChain = vi.fn()
  const deps = {
    userId: 'u1',
    getGroup,
    getChain,
    sealPostEdit,
    editPost: edit,
  } as unknown as EditPostDeps
  const run = (over: { resend?: SealedPostEdit } = {}) =>
    submitPostEdit(deps, {
      groupId: 'g',
      postId: POST,
      sortKey: SORT_KEY,
      title: 'new title',
      body: 'new body',
      at: AT,
      ...over,
    })
  return { run, sealPostEdit, edit, getGroup, getChain }
}

const conflict = (code: string) => new ApiError(409, code, code)

describe('submitPostEdit', () => {
  it('seals once under the post sort key with the original time and sends it to the post id', async () => {
    const s = setup()
    expect(await s.run()).toEqual({ ok: true })
    expect(s.sealPostEdit.mock.calls[0]![0]).toMatchObject({
      userId: 'u1',
      groupId: 'g',
      sortKey: SORT_KEY,
      generation: 3,
      postGeneration: 3,
      title: 'new title',
      body: 'new body',
      at: AT,
    })
    expect(s.edit).toHaveBeenCalledTimes(1)
    expect(s.edit.mock.calls[0]![0]).toBe(POST)
    expect(s.edit.mock.calls[0]![1]).toEqual({
      generation: 3,
      signedDay: '2026-10-31',
      nonce: 'n1',
      ciphertext: 'ct',
      signature: 'sig',
    })
  })

  it('seals under the generation new posts use, with the chain down to it, while a rotation runs', async () => {
    const s = setup()
    // The caller's own wrap is at generation 3; a rotation to 3 is running, so posts still use 2.
    s.getGroup.mockResolvedValue({
      groupId: 'g',
      role: 'member',
      generation: 3,
      rotation: { generation: 3 },
      wrappedGroupKey: WRAPPED,
    } as unknown as GroupDetail)
    const chain = [{ generation: 2, wrapped: { nonce: 'n', ciphertext: 'c' } }]
    s.getChain.mockResolvedValue(chain)
    expect(await s.run()).toEqual({ ok: true })
    expect(s.getChain).toHaveBeenCalledWith('g', 2, 3)
    expect(s.sealPostEdit.mock.calls[0]![0]).toMatchObject({
      generation: 3,
      postGeneration: 2,
      chain,
    })
  })

  it('sends the SAME bytes again after conflict_retry, without sealing again', async () => {
    const edit = vi.fn().mockRejectedValueOnce(conflict('conflict_retry'))
    edit.mockResolvedValue({ sortKey: SORT_KEY })
    const s = setup(edit)
    expect(await s.run()).toEqual({ ok: true })
    expect(s.sealPostEdit).toHaveBeenCalledTimes(1)
    expect(edit.mock.calls[1]![1]).toEqual(edit.mock.calls[0]![1])
  })

  it('seals AGAIN after generation_stale, loading the group again', async () => {
    const edit = vi.fn().mockRejectedValueOnce(conflict('generation_stale'))
    edit.mockResolvedValue({ sortKey: SORT_KEY })
    const s = setup(edit)
    expect(await s.run()).toEqual({ ok: true })
    expect(s.sealPostEdit).toHaveBeenCalledTimes(2)
    expect(s.getGroup).toHaveBeenCalledTimes(2)
  })

  it('reports a refused signing day (clock_skew) as clockSkew, without retrying or resealing', async () => {
    const s = setup(
      vi.fn().mockRejectedValue(new ApiError(400, 'signedDay: not within tolerance', 'clock_skew')),
    )
    expect(await s.run()).toEqual({ ok: false, kind: 'clockSkew' })
    expect(s.edit).toHaveBeenCalledTimes(1)
  })

  it('reports post_gone as gone, without retrying', async () => {
    const s = setup(vi.fn().mockRejectedValue(conflict('post_gone')))
    expect(await s.run()).toEqual({ ok: false, kind: 'gone' })
    expect(s.edit).toHaveBeenCalledTimes(1)
  })

  it('keeps the sealed bytes when no answer came, and resends exactly those', async () => {
    const edit = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    edit.mockResolvedValue({ sortKey: SORT_KEY })
    const s = setup(edit)
    const first = await s.run()
    expect(first).toMatchObject({ ok: false, kind: 'ambiguous' })
    const kept = (first as { sealed: SealedPostEdit }).sealed
    expect(await s.run({ resend: kept })).toEqual({ ok: true })
    expect(s.sealPostEdit).toHaveBeenCalledTimes(1)
    expect(edit.mock.calls[1]![1]).toEqual(edit.mock.calls[0]![1])
  })

  it('asks for the password with no live keys, says unreadable for another seal failure, and reports an unloadable group', async () => {
    const s = setup()
    s.sealPostEdit.mockRejectedValueOnce(new Error('worker: no live keys cached -- log in again'))
    expect(await s.run()).toEqual({ ok: false, kind: 'coldKeys' })
    s.sealPostEdit.mockRejectedValueOnce(new Error('bad tag'))
    expect(await s.run()).toEqual({ ok: false, kind: 'unreadable' })
    s.getGroup.mockRejectedValue(new ApiError(404, 'no'))
    expect(await s.run()).toEqual({ ok: false, kind: 'notFound' })
    expect(s.edit).not.toHaveBeenCalled()
  })

  it('maps the member and session answers without retrying', async () => {
    for (const [err, kind] of [
      [new ApiError(401, 'no'), 'authRequired'],
      [new ApiError(404, 'no'), 'notFound'],
      [conflict('member_behind'), 'behind'],
      [conflict('member_dormant'), 'dormant'],
    ] as const) {
      const s = setup(vi.fn().mockRejectedValue(err))
      expect(await s.run()).toEqual({ ok: false, kind })
      expect(s.edit).toHaveBeenCalledTimes(1)
    }
  })

  it('gives up as busy when conflict_retry never clears', async () => {
    const s = setup(vi.fn().mockRejectedValue(conflict('conflict_retry')))
    expect(await s.run()).toEqual({ ok: false, kind: 'busy' })
    expect(s.edit).toHaveBeenCalledTimes(MAX_EDIT_RETRIES + 1)
  })
})

describe('classifyEditError and the gone code', () => {
  it('treats only the given code as gone: a post is not told "comment_gone"', () => {
    expect(classifyEditError(conflict('post_gone'), 'post_gone')).toEqual({ fail: 'gone' })
    expect(classifyEditError(conflict('comment_gone'), 'post_gone')).toMatchObject({
      fail: 'rejected',
    })
    expect(classifyEditError(conflict('post_gone'), 'comment_gone')).toMatchObject({
      fail: 'rejected',
    })
  })
})
