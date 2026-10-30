import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { SealedComment } from '@/lib/crypto/worker-protocol'
import {
  INITIAL_REPLY_STATE,
  nextReplyState,
  TARGET_GONE_MESSAGE,
  type ReplyEvent,
  type ReplyState,
} from './replyState'
import type { SubmitDeps } from './runCreateComment'
import type { CommentView, ThreadPageResult } from './runLoadThread'
import { INITIAL_THREAD_STATE, nextThreadState, type ThreadEvent } from './threadState'
import {
  loadPageInto,
  sendReply,
  SEND_ERRORS,
  type PendingReply,
  type SavedReply,
  type ThreadIO,
} from './threadWiring'

const WRAPPED = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }
const POST = 'g#2026-10-29#00112233445566ff'

const view = (path: string): CommentView => ({
  path,
  depth: path.split('.').length,
  authorUserId: 'u',
  authorName: 'alice',
  signedDay: '2026-10-29',
  content: { kind: 'opened', text: path, at: '2026-10-29T00:00:00.000Z', timeSuspect: false },
  signature: { kind: 'valid' },
})
const page = (paths: string[], nextCursor?: string): ThreadPageResult => ({
  ok: true,
  comments: paths.map(view),
  ...(nextCursor !== undefined && { nextCursor }),
})

/** The real reducers behind fake dispatchers, so a scenario runs the way the screen does. */
function harness(reply: Partial<ReplyState> = {}) {
  let thread = INITIAL_THREAD_STATE
  let replyState: ReplyState = { ...INITIAL_REPLY_STATE, ...reply }
  const coldKeys = vi.fn()
  const io: ThreadIO = {
    dispatch: (e: ThreadEvent) => {
      thread = nextThreadState(thread, e)
    },
    dispatchReply: (e: ReplyEvent) => {
      replyState = nextReplyState(replyState, e)
    },
    onColdKeys: coldKeys,
    liveReply: () =>
      replyState.draft === ''
        ? undefined
        : { replyTo: replyState.replyTo, draft: replyState.draft },
  }
  return {
    io,
    coldKeys,
    thread: () => thread,
    reply: () => replyState,
  }
}

describe('loadPageInto', () => {
  it('tells the reply box which comments the first page holds, dropping a missing target', async () => {
    const h = harness({ replyTo: '0001', draft: 'typed' })
    await loadPageInto(
      h.io,
      () => Promise.resolve(page(['0002'])),
      () => true,
      undefined,
      false,
    )
    expect(h.thread().comments.map((c) => c.path)).toEqual(['0002'])
    expect(h.reply()).toMatchObject({ replyTo: null, draft: 'typed', error: TARGET_GONE_MESSAGE })
  })

  it('keeps a target that is on the first page', async () => {
    const h = harness({ replyTo: '0001', draft: 'typed' })
    await loadPageInto(
      h.io,
      () => Promise.resolve(page(['0001'])),
      () => true,
      undefined,
      false,
    )
    expect(h.reply().replyTo).toBe('0001')
  })

  it('does not drop the target on a later page, where the first page is already on screen', async () => {
    const h = harness({ replyTo: '0001', draft: 'typed' })
    await loadPageInto(
      h.io,
      () => Promise.resolve(page(['0060'])),
      () => true,
      'cur',
      true,
    )
    expect(h.reply().replyTo).toBe('0001')
  })

  it('drops a page that arrives after the thread started over', async () => {
    const h = harness({ replyTo: '0001', draft: 'typed' })
    await loadPageInto(
      h.io,
      () => Promise.resolve(page(['0002'])),
      () => false,
      undefined,
      true,
    )
    // Only the start of the load was announced; the stale result changed nothing.
    expect(h.thread().comments).toEqual([])
    expect(h.reply().replyTo).toBe('0001')
  })

  it('announces a load only when asked', async () => {
    const seen: string[] = []
    const h = harness()
    const io = { ...h.io, dispatch: (e: ThreadEvent) => void seen.push(e.type) }
    await loadPageInto(
      io,
      () => Promise.resolve(page([])),
      () => true,
      undefined,
      true,
    )
    await loadPageInto(
      io,
      () => Promise.resolve(page([])),
      () => true,
      undefined,
      false,
    )
    expect(seen).toEqual(['loadStarted', 'pageLoaded', 'pageLoaded'])
  })

  it('asks for the password with what is in the box right now, and nothing when it is empty', async () => {
    const cold: ThreadPageResult = { ok: false, kind: 'coldKeys' }
    const typed = harness({ replyTo: '0004', draft: 'half written' })
    await loadPageInto(
      typed.io,
      () => Promise.resolve(cold),
      () => true,
      undefined,
      false,
    )
    expect(typed.coldKeys).toHaveBeenCalledWith({ replyTo: '0004', draft: 'half written' })
    // A failed load is not a first page: the target stays.
    expect(typed.reply().replyTo).toBe('0004')

    const empty = harness({ replyTo: '0004', draft: '' })
    await loadPageInto(
      empty.io,
      () => Promise.resolve(cold),
      () => true,
      undefined,
      false,
    )
    expect(empty.coldKeys).toHaveBeenCalledWith(undefined)
  })
})

function sendHarness(h: ReturnType<typeof harness>, createComment = vi.fn()) {
  const sealComment = vi.fn((req: { path: string }) =>
    Promise.resolve({
      path: req.path,
      generation: 0,
      signedDay: '2026-10-29',
      nonce: `n-${req.path}`,
      ciphertext: `c-${req.path}`,
      signature: `s-${req.path}`,
    } satisfies SealedComment),
  )
  const pending: { current: PendingReply | null } = { current: null }
  const reload = vi.fn()
  const deps = {
    context: {
      getGroup: vi.fn().mockResolvedValue({
        groupId: 'g',
        role: 'member',
        generation: 0,
        wrappedGroupKey: WRAPPED,
      } as unknown as GroupDetail),
      getChain: vi.fn(),
    },
    submit: { userId: 'u1', sealComment, createComment } as unknown as SubmitDeps,
    pending,
  }
  const send = (over: { replyTo?: string | null; text?: string; loadedPaths?: string[] } = {}) =>
    sendReply({ ...h.io, reload }, deps, {
      groupId: 'g',
      postId: POST,
      replyTo: h.reply().replyTo,
      text: h.reply().draft,
      loadedPaths: [],
      ...over,
    })
  return { send, sealComment, createComment, pending, reload, deps }
}

describe('sendReply', () => {
  it('after parent_gone, reloads and the next Send is a top-level comment, not a reply to the gone one', async () => {
    // Round 1's blocking finding, end to end: the reply box aimed at 0001, which was deleted.
    const h = harness({ replyTo: '0001', draft: 'my reply' })
    const created = vi.fn().mockRejectedValueOnce(new ApiError(409, 'gone', 'parent_gone'))
    created.mockResolvedValue({ path: 'ok' })
    const s = sendHarness(h, created)
    // The reload loads the first page again; only 0002 is left.
    s.reload.mockImplementation(() => {
      void loadPageInto(
        h.io,
        () => Promise.resolve(page(['0002'])),
        () => true,
        undefined,
        true,
      )
    })

    await s.send({ loadedPaths: ['0001', '0002'] })
    expect(created.mock.calls[0]![1].path).toBe('0001.0001')
    expect(s.reload).toHaveBeenCalledTimes(1)
    await vi.waitFor(() => {
      expect(h.reply().replyTo).toBeNull()
    })
    expect(h.reply()).toMatchObject({
      draft: 'my reply',
      sending: false,
      error: TARGET_GONE_MESSAGE,
    })

    await s.send({ loadedPaths: h.thread().comments.map((c) => c.path) })
    expect(created.mock.calls[1]![1].path).toBe('0003')
    expect(h.reply()).toMatchObject({ draft: '', notice: 'Comment sent.', replyTo: null })
  })

  it('guesses the next number under the target from the comments on screen', async () => {
    const h = harness({ replyTo: '0001', draft: 'x' })
    const s = sendHarness(h, vi.fn().mockResolvedValue({ path: 'ok' }))
    await s.send({ loadedPaths: ['0001', '0001.0001', '0002'] })
    expect(s.createComment.mock.calls[0]![1].path).toBe('0001.0002')
    expect(s.reload).toHaveBeenCalledTimes(1)
    expect(h.reply().notice).toBe('Comment sent.')
  })

  it('sends the same sealed bytes again after a lost answer, and seals fresh once the text changes', async () => {
    const h = harness({ replyTo: null, draft: 'one' })
    const created = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    created.mockResolvedValue({ path: 'ok' })
    const s = sendHarness(h, created)

    await s.send()
    expect(h.reply()).toMatchObject({ sending: false, error: SEND_ERRORS.ambiguous })
    expect(s.pending.current).not.toBeNull()

    await s.send()
    expect(s.sealComment).toHaveBeenCalledTimes(1)
    expect(created.mock.calls[1]![1]).toEqual(created.mock.calls[0]![1])
    expect(s.pending.current).toBeNull()

    // A different draft, or a different target, never reuses a kept seal.
    const h2 = harness({ replyTo: null, draft: 'one' })
    const c2 = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    c2.mockResolvedValue({ path: 'ok' })
    const s2 = sendHarness(h2, c2)
    await s2.send()
    await s2.send({ text: 'two' })
    expect(s2.sealComment).toHaveBeenCalledTimes(2)
    expect(s2.pending.current).toBeNull()
  })

  it('does not reuse a kept seal for the same text aimed at another comment', async () => {
    const h = harness({ replyTo: null, draft: 'same words' })
    const created = vi.fn().mockRejectedValueOnce(new TypeError('lost'))
    created.mockResolvedValue({ path: 'ok' })
    const s = sendHarness(h, created)
    await s.send()
    await s.send({ replyTo: '0001' })
    expect(s.sealComment).toHaveBeenCalledTimes(2)
    expect(created.mock.calls.map((c) => c[1].path)).toEqual(['0001', '0001.0001'])
  })

  it('hands the password step the reply it was sending', async () => {
    const h = harness({ replyTo: '0004', draft: 'half written' })
    const s = sendHarness(h)
    s.sealComment.mockRejectedValue(new Error('no live keys cached'))
    await s.send()
    expect(h.coldKeys).toHaveBeenCalledWith({ replyTo: '0004', draft: 'half written' })
    expect(h.reply()).toMatchObject({ sending: false, error: SEND_ERRORS.coldKeys })
  })

  it('reports a group that cannot be loaded without sealing or sending', async () => {
    const h = harness({ draft: 'x' })
    const s = sendHarness(h)
    s.deps.context.getGroup.mockRejectedValue(new ApiError(404, 'no'))
    await s.send()
    expect(s.sealComment).not.toHaveBeenCalled()
    expect(s.createComment).not.toHaveBeenCalled()
    expect(h.reply().error).toBe(SEND_ERRORS.notFound)
  })

  it('does not reload for a failure other than a gone parent', async () => {
    const h = harness({ draft: 'x' })
    const s = sendHarness(h, vi.fn().mockRejectedValue(new ApiError(409, 'full', 'replies_full')))
    await s.send()
    expect(s.reload).not.toHaveBeenCalled()
    expect(h.reply().error).toBe(SEND_ERRORS.repliesFull)
  })
})

describe('SavedReply', () => {
  it('is what the password step keeps', () => {
    const r: SavedReply = { replyTo: null, draft: 'x' }
    expect(r.draft).toBe('x')
  })
})
