import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { SealedPostEdit } from '@/lib/crypto/worker-protocol'
import {
  INITIAL_POST_CONTROLS_STATE,
  nextPostControlsState,
  type PostControlsEvent,
  type PostControlsState,
} from './postControls'
import {
  confirmDeletePost,
  POST_DELETE_ERRORS,
  POST_EDIT_ERRORS,
  saveEditPost,
  type PendingPostEdit,
} from './postWiring'
import { CLOCK_SKEW_MESSAGE } from './replyState'
import type { EditPostDeps } from './runEditPost'

const SORT_KEY = 'POST#2026-10-29#00112233445566ff'
const POST = `g#${SORT_KEY.slice(5)}`
const WRAPPED = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }

function harness() {
  let controls: PostControlsState = INITIAL_POST_CONTROLS_STATE
  const reload = vi.fn()
  const coldKeys = vi.fn()
  const io = {
    dispatchControls: (e: PostControlsEvent) => {
      controls = nextPostControlsState(controls, e)
    },
    reload,
    onColdKeys: coldKeys,
  }
  return { io, reload, coldKeys, controls: () => controls }
}

function editHarness(
  h: ReturnType<typeof harness>,
  editPost: ReturnType<typeof vi.fn> = vi.fn().mockResolvedValue({ sortKey: SORT_KEY }),
) {
  const sealPostEdit = vi.fn().mockResolvedValue({
    sortKey: SORT_KEY,
    generation: 0,
    signedDay: '2026-10-31',
    nonce: 'n',
    ciphertext: 'c',
    signature: 's',
  } satisfies SealedPostEdit)
  const pending: { current: PendingPostEdit | null } = { current: null }
  const edit = {
    userId: 'u1',
    getGroup: vi.fn().mockResolvedValue({
      groupId: 'g',
      role: 'member',
      generation: 0,
      wrappedGroupKey: WRAPPED,
    } as unknown as GroupDetail),
    getChain: vi.fn(),
    sealPostEdit,
    editPost,
  } as unknown as EditPostDeps
  const open = () => {
    h.io.dispatchControls({ type: 'editOpened', sortKey: SORT_KEY, title: 'old', body: 'old body' })
  }
  const save = (title = 'new', body = 'new body') =>
    saveEditPost(
      h.io,
      { edit, pending },
      {
        groupId: 'g',
        postId: POST,
        sortKey: SORT_KEY,
        title,
        body,
        at: '2026-10-29T00:00:00.000Z',
      },
    )
  const saveAt = (sortKey: string) =>
    saveEditPost(
      h.io,
      { edit, pending },
      {
        groupId: 'g',
        postId: `g#${sortKey.slice(5)}`,
        sortKey,
        title: 'new',
        body: 'new body',
        at: '2026-10-29T00:00:00.000Z',
      },
    )
  return { open, save, saveAt, sealPostEdit, editPost, pending }
}

describe('saveEditPost', () => {
  it('closes the form and reloads the list when the edit lands', async () => {
    const h = harness()
    const e = editHarness(h)
    e.open()
    await e.save()
    expect(h.controls()).toMatchObject({ mode: { kind: 'idle' }, busy: false, error: null })
    expect(h.reload).toHaveBeenCalledTimes(1)
  })

  it('sends the same bytes again after a lost answer while the text is unchanged, and seals fresh when the title or the body changes', async () => {
    const h = harness()
    const put = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    put.mockResolvedValue({ sortKey: SORT_KEY })
    const e = editHarness(h, put)
    e.open()
    await e.save()
    expect(h.controls()).toMatchObject({ busy: false, error: POST_EDIT_ERRORS.ambiguous })
    expect(h.controls().mode.kind).toBe('editing')
    expect(e.pending.current).not.toBeNull()
    await e.save()
    expect(e.sealPostEdit).toHaveBeenCalledTimes(1)
    expect(put.mock.calls[1]![1]).toEqual(put.mock.calls[0]![1])
    expect(e.pending.current).toBeNull()

    for (const [title, body] of [
      ['other title', 'new body'],
      ['new', 'other body'],
    ] as const) {
      const h2 = harness()
      const put2 = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
      put2.mockResolvedValue({ sortKey: SORT_KEY })
      const e2 = editHarness(h2, put2)
      e2.open()
      await e2.save()
      await e2.save(title, body)
      expect(e2.sealPostEdit, `${title}/${body}`).toHaveBeenCalledTimes(2)
    }
  })

  it('does not reuse a kept seal for the same text on another post', async () => {
    const h = harness()
    const put = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    put.mockResolvedValue({ sortKey: SORT_KEY })
    const e = editHarness(h, put)
    e.open()
    await e.save()
    expect(e.pending.current).not.toBeNull()
    await e.saveAt('POST#2026-10-29#aaaaaaaaaaaaaaaa')
    expect(e.sealPostEdit).toHaveBeenCalledTimes(2)
  })

  it('reloads when the post was deleted meanwhile, and the form closes with the reason kept', async () => {
    const h = harness()
    const e = editHarness(h, vi.fn().mockRejectedValue(new ApiError(409, 'gone', 'post_gone')))
    e.open()
    await e.save()
    expect(h.reload).toHaveBeenCalledTimes(1)
    expect(h.controls().error).toBe(POST_EDIT_ERRORS.gone)
    h.io.dispatchControls({ type: 'firstPageLoaded', liveKeys: [] })
    expect(h.controls()).toMatchObject({ mode: { kind: 'idle' }, error: POST_EDIT_ERRORS.gone })
  })

  it('keeps the form and says the device clock looks wrong when the signing day is refused', async () => {
    const h = harness()
    const e = editHarness(
      h,
      vi.fn().mockRejectedValue(new ApiError(400, 'signedDay: no', 'clock_skew')),
    )
    e.open()
    await e.save()
    expect(h.controls().error).toBe(POST_EDIT_ERRORS.clockSkew)
    expect(h.controls().error).toBe(CLOCK_SKEW_MESSAGE)
    expect(h.controls().mode.kind).toBe('editing')
    expect(h.reload).not.toHaveBeenCalled()
  })

  it('forgets an edit resend refused as clock_skew, so the next Save seals fresh', async () => {
    const h = harness()
    const edit = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    edit.mockRejectedValueOnce(new ApiError(400, 'signedDay: no', 'clock_skew'))
    edit.mockResolvedValue({ sortKey: SORT_KEY })
    const e = editHarness(h, edit)
    e.open()
    await e.save()
    expect(e.pending.current).not.toBeNull()
    await e.save()
    expect(h.controls().error).toBe(CLOCK_SKEW_MESSAGE)
    expect(e.pending.current).toBeNull()
    await e.save()
    expect(e.sealPostEdit).toHaveBeenCalledTimes(2)
  })

  it('keeps the form and the draft on a rejection, with the server message', async () => {
    const h = harness()
    const e = editHarness(
      h,
      vi.fn().mockRejectedValue(new ApiError(403, 'only the author can edit a post')),
    )
    e.open()
    await e.save()
    expect(h.controls()).toMatchObject({
      error: 'only the author can edit a post',
      mode: { kind: 'editing' },
    })
    expect(h.reload).not.toHaveBeenCalled()
  })

  it('asks for the password when there are no live keys', async () => {
    const h = harness()
    const e = editHarness(h)
    e.sealPostEdit.mockRejectedValue(new Error('no live keys cached'))
    e.open()
    await e.save()
    expect(h.coldKeys).toHaveBeenCalledTimes(1)
    expect(h.controls().error).toBe(POST_EDIT_ERRORS.coldKeys)
  })
})

describe('confirmDeletePost', () => {
  const run = (h: ReturnType<typeof harness>, del: ReturnType<typeof vi.fn>) => {
    h.io.dispatchControls({ type: 'deleteAsked', sortKey: SORT_KEY })
    return () =>
      confirmDeletePost(
        h.io,
        { deletePost: del as unknown as (postId: string) => Promise<void> },
        { postId: POST },
      )
  }

  it('closes the confirmation and reloads when the delete lands', async () => {
    const h = harness()
    const del = vi.fn().mockResolvedValue(undefined)
    await run(h, del)()
    expect(del).toHaveBeenCalledWith(POST)
    expect(h.controls()).toMatchObject({ mode: { kind: 'idle' }, busy: false, error: null })
    expect(h.reload).toHaveBeenCalledTimes(1)
  })

  it('keeps the confirmation open on a failure with no clear answer, so Delete can be pressed again', async () => {
    const h = harness()
    await run(h, vi.fn().mockRejectedValue(new TypeError('lost')))()
    expect(h.controls()).toMatchObject({
      mode: { kind: 'confirmDelete' },
      busy: false,
      error: POST_DELETE_ERRORS.failed,
    })
    expect(h.reload).not.toHaveBeenCalled()
  })

  it('reloads when the post is gone (404)', async () => {
    const h = harness()
    await run(h, vi.fn().mockRejectedValue(new ApiError(404, 'post not found')))()
    expect(h.controls().error).toBe(POST_DELETE_ERRORS.gone)
    expect(h.reload).toHaveBeenCalledTimes(1)
  })

  it('shows the server message on 403 and asks to log in on 401', async () => {
    const h = harness()
    await run(
      h,
      vi.fn().mockRejectedValue(new ApiError(403, 'only the author or an admin can delete a post')),
    )()
    expect(h.controls().error).toBe('only the author or an admin can delete a post')
    const h2 = harness()
    await run(h2, vi.fn().mockRejectedValue(new ApiError(401, 'nope')))()
    expect(h2.controls().error).toBe(POST_DELETE_ERRORS.authRequired)
  })
})
