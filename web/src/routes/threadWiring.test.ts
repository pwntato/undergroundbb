import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { SealedComment, SealedReaction } from '@/lib/crypto/worker-protocol'
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
  classifyReactionError,
  loadPageInto,
  MAX_REACTION_RESEALS,
  MAX_REACTION_RETRIES,
  REACTION_ERRORS,
  sendReply,
  SEND_ERRORS,
  toggleReaction,
  type PendingReply,
  type ReactDeps,
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
  reactions: [],
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

function reactHarness(
  h: ReturnType<typeof harness>,
  over: { put?: ReturnType<typeof vi.fn>; del?: ReturnType<typeof vi.fn> } = {},
) {
  const sealReaction = vi.fn((req: { index: number; reactionGeneration: number }) =>
    Promise.resolve({
      generation: req.reactionGeneration,
      nonce: `n${String(req.index)}`,
      ciphertext: `c${String(req.index)}`,
    } satisfies SealedReaction),
  )
  const putReaction = over.put ?? vi.fn().mockResolvedValue(undefined)
  const deleteReaction = over.del ?? vi.fn().mockResolvedValue(undefined)
  const reload = vi.fn()
  const context = {
    getGroup: vi.fn().mockResolvedValue({
      groupId: 'g',
      role: 'member',
      generation: 0,
      wrappedGroupKey: WRAPPED,
    } as unknown as GroupDetail),
    getChain: vi.fn(),
  }
  const deps = { userId: 'u1', context, sealReaction, putReaction, deleteReaction } as ReactDeps
  const press = (target: string, index: number, mine: number | null = null) =>
    toggleReaction({ ...h.io, reload }, deps, { groupId: 'g', postId: POST, target, index, mine })
  return { press, sealReaction, putReaction, deleteReaction, reload, context }
}

const mineOn = (h: ReturnType<typeof harness>, target: string) =>
  h.thread().reactions.find((x) => x.target === target && x.reactorUserId === 'u1')?.index

function withReaction(h: ReturnType<typeof harness>, target: string, index: number) {
  h.io.dispatch({ type: 'reactionSaved', target, reactorUserId: 'u1', index })
}

describe('toggleReaction', () => {
  it("seals the pressed reaction for the target, sends it, and only then shows it as the reader's", async () => {
    const h = harness()
    let seenWhileSending: unknown
    const put = vi.fn(() => {
      seenWhileSending = { reacting: h.thread().reacting, shown: mineOn(h, '0001') }
      return Promise.resolve()
    })
    const r = reactHarness(h, { put })
    await r.press('0001', 3)
    expect(r.sealReaction).toHaveBeenCalledWith({
      userId: 'u1',
      groupId: 'g',
      postId: POST,
      target: '0001',
      generation: 0,
      reactionGeneration: 0,
      wrappedGroupKey: WRAPPED,
      index: 3,
    })
    expect(put).toHaveBeenCalledWith(POST, '0001', { generation: 0, nonce: 'n3', ciphertext: 'c3' })
    expect(seenWhileSending).toEqual({ reacting: ['0001'], shown: undefined })
    expect(mineOn(h, '0001')).toBe(3)
    expect(h.thread()).toMatchObject({ reacting: [], reactionError: null })
    expect(r.deleteReaction).not.toHaveBeenCalled()
  })

  it('works on the post itself, target 0000', async () => {
    const h = harness()
    const r = reactHarness(h)
    await r.press('0000', 7)
    expect(r.putReaction).toHaveBeenCalledWith(POST, '0000', expect.anything())
    expect(mineOn(h, '0000')).toBe(7)
  })

  it('seals under the generation new items use while a rotation runs, and walks the chain to it', async () => {
    const h = harness()
    const r = reactHarness(h)
    const chain = [{ generation: 0, wrapped: { nonce: 'a', ciphertext: 'b' } }]
    r.context.getGroup.mockResolvedValue({
      groupId: 'g',
      role: 'member',
      generation: 1,
      rotation: { generation: 1 },
      wrappedGroupKey: WRAPPED,
    } as unknown as GroupDetail)
    r.context.getChain.mockResolvedValue(chain)
    await r.press('0001', 2)
    expect(r.context.getChain).toHaveBeenCalledWith('g', 0, 1)
    expect(r.sealReaction.mock.calls[0]![0]).toMatchObject({
      generation: 1,
      reactionGeneration: 0,
      chain,
    })
    expect(r.putReaction.mock.calls[0]![2].generation).toBe(0)
  })

  it("replaces the reader's own reaction when another is pressed", async () => {
    const h = harness()
    withReaction(h, '0001', 2)
    const r = reactHarness(h)
    await r.press('0001', 5, 2)
    expect(r.putReaction).toHaveBeenCalledTimes(1)
    expect(r.deleteReaction).not.toHaveBeenCalled()
    expect(h.thread().reactions.filter((x) => x.target === '0001')).toEqual([
      { target: '0001', reactorUserId: 'u1', index: 5 },
    ])
  })

  it("takes the reader's reaction back when the same one is pressed, with nothing sealed", async () => {
    const h = harness()
    withReaction(h, '0001', 2)
    withReaction(h, '0002', 4)
    const r = reactHarness(h)
    await r.press('0001', 2, 2)
    expect(r.deleteReaction).toHaveBeenCalledWith(POST, '0001')
    expect(r.putReaction).not.toHaveBeenCalled()
    expect(r.sealReaction).not.toHaveBeenCalled()
    expect(r.context.getGroup).not.toHaveBeenCalled()
    expect(mineOn(h, '0001')).toBeUndefined()
    expect(mineOn(h, '0002')).toBe(4)
  })

  it.each([
    [401, undefined, REACTION_ERRORS.authRequired],
    [404, undefined, REACTION_ERRORS.notFound],
    [409, 'member_behind', REACTION_ERRORS.behind],
    [409, 'member_dormant', REACTION_ERRORS.dormant],
    [500, undefined, REACTION_ERRORS.failed],
    [502, undefined, REACTION_ERRORS.failed],
  ])(
    'a %i %s while saving shows its message and changes no reaction',
    async (status, code, message) => {
      const h = harness()
      withReaction(h, '0001', 2)
      const r = reactHarness(h, { put: vi.fn().mockRejectedValue(new ApiError(status, 'x', code)) })
      await r.press('0001', 5, 2)
      expect(h.thread().reactionError).toEqual({ target: '0001', message })
      expect(h.thread()).toMatchObject({ reacting: [] })
      expect(mineOn(h, '0001')).toBe(2)
      expect(r.reload).not.toHaveBeenCalled()
    },
  )

  it('treats a network failure as a failed save, not an exception', async () => {
    const h = harness()
    const r = reactHarness(h, { put: vi.fn().mockRejectedValue(new TypeError('Failed to fetch')) })
    await r.press('0001', 1)
    expect(h.thread().reactionError?.message).toBe(REACTION_ERRORS.failed)
    expect(mineOn(h, '0001')).toBeUndefined()
  })

  it("shows the server's own words for a refusal it does not know", async () => {
    const h = harness()
    const r = reactHarness(h, {
      put: vi.fn().mockRejectedValue(new ApiError(400, 'ciphertext: wrong length')),
    })
    await r.press('0001', 1)
    expect(h.thread().reactionError?.message).toBe('ciphertext: wrong length')
  })

  it('reloads the thread when the comment reacted to is gone', async () => {
    const h = harness()
    const r = reactHarness(h, {
      put: vi.fn().mockRejectedValue(new ApiError(409, 'gone', 'parent_gone')),
    })
    await r.press('0001', 1)
    expect(h.thread().reactionError?.message).toBe(REACTION_ERRORS.parentGone)
    expect(r.reload).toHaveBeenCalledTimes(1)
  })

  it('sends the same bytes again after a write collision, and seals once', async () => {
    const h = harness()
    const put = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(409, 'busy', 'conflict_retry'))
      .mockRejectedValueOnce(new ApiError(409, 'busy', 'conflict_retry'))
      .mockResolvedValue(undefined)
    const r = reactHarness(h, { put })
    await r.press('0001', 4)
    expect(put).toHaveBeenCalledTimes(3)
    expect(put.mock.calls[1]).toEqual(put.mock.calls[0])
    expect(put.mock.calls[2]).toEqual(put.mock.calls[0])
    expect(r.sealReaction).toHaveBeenCalledTimes(1)
    expect(mineOn(h, '0001')).toBe(4)
  })

  it('gives up after the retries and says others are reacting', async () => {
    const h = harness()
    const put = vi.fn().mockRejectedValue(new ApiError(409, 'busy', 'conflict_retry'))
    const r = reactHarness(h, { put })
    await r.press('0001', 4)
    expect(put).toHaveBeenCalledTimes(1 + MAX_REACTION_RETRIES)
    expect(h.thread().reactionError?.message).toBe(REACTION_ERRORS.busy)
    expect(mineOn(h, '0001')).toBeUndefined()
  })

  it('retries taking a reaction back after a collision too', async () => {
    const h = harness()
    withReaction(h, '0001', 2)
    const del = vi
      .fn()
      .mockRejectedValueOnce(new ApiError(409, 'busy', 'conflict_retry'))
      .mockResolvedValue(undefined)
    const r = reactHarness(h, { del })
    await r.press('0001', 2, 2)
    expect(del).toHaveBeenCalledTimes(2)
    expect(mineOn(h, '0001')).toBeUndefined()
  })

  it.each(['generation_stale', 'membership_changed', 'key_epoch_stale'])(
    'on %s loads the group again and seals a fresh reaction',
    async (code) => {
      const h = harness()
      const put = vi
        .fn()
        .mockRejectedValueOnce(new ApiError(409, 'stale', code))
        .mockResolvedValue(undefined)
      const r = reactHarness(h, { put })
      await r.press('0001', 6)
      expect(r.context.getGroup).toHaveBeenCalledTimes(2)
      expect(r.sealReaction).toHaveBeenCalledTimes(2)
      expect(put).toHaveBeenCalledTimes(2)
      expect(mineOn(h, '0001')).toBe(6)
    },
  )

  it('stops sealing again after the reseals and says the group changed', async () => {
    const h = harness()
    const put = vi.fn().mockRejectedValue(new ApiError(409, 'stale', 'generation_stale'))
    const r = reactHarness(h, { put })
    await r.press('0001', 6)
    expect(r.sealReaction).toHaveBeenCalledTimes(1 + MAX_REACTION_RESEALS)
    expect(put).toHaveBeenCalledTimes(1 + MAX_REACTION_RESEALS)
    expect(h.thread().reactionError?.message).toBe(REACTION_ERRORS.reseal)
  })

  it('shows a failed take-back in its own words and keeps the reaction', async () => {
    const h = harness()
    withReaction(h, '0001', 2)
    const r = reactHarness(h, { del: vi.fn().mockRejectedValue(new ApiError(500, 'x')) })
    await r.press('0001', 2, 2)
    expect(h.thread().reactionError).toEqual({
      target: '0001',
      message: REACTION_ERRORS.removeFailed,
    })
    expect(mineOn(h, '0001')).toBe(2)
  })

  it('reports a group that cannot be loaded without sealing or sending', async () => {
    const h = harness()
    const r = reactHarness(h)
    r.context.getGroup.mockRejectedValue(new ApiError(404, 'no'))
    await r.press('0001', 1)
    expect(r.sealReaction).not.toHaveBeenCalled()
    expect(r.putReaction).not.toHaveBeenCalled()
    expect(h.thread().reactionError?.message).toBe(REACTION_ERRORS.notFound)
  })

  it('asks for the password with what is in the reply box, and sends nothing, when the keys are cold', async () => {
    const h = harness({ replyTo: '0001', draft: 'typed so far' })
    const r = reactHarness(h)
    r.sealReaction.mockRejectedValue(new Error('no live keys cached'))
    await r.press('0001', 1)
    expect(h.coldKeys).toHaveBeenCalledWith({ replyTo: '0001', draft: 'typed so far' })
    expect(r.putReaction).not.toHaveBeenCalled()
    expect(h.thread().reactionError?.message).toBe(REACTION_ERRORS.coldKeys)
  })

  it('does not ask for the password for any other sealing failure', async () => {
    const h = harness()
    const r = reactHarness(h)
    r.sealReaction.mockRejectedValue(new Error('crypto: link missing'))
    await r.press('0001', 1)
    expect(h.coldKeys).not.toHaveBeenCalled()
    expect(h.thread().reactionError?.message).toBe(REACTION_ERRORS.unreadable)
  })
})

describe('classifyReactionError', () => {
  it.each([
    [new ApiError(409, 'x', 'conflict_retry'), 'retry'],
    [new ApiError(409, 'x', 'generation_stale'), 'reseal'],
    [new ApiError(409, 'x', 'membership_changed'), 'reseal'],
    [new ApiError(409, 'x', 'key_epoch_stale'), 'reseal'],
    [new ApiError(409, 'x', 'member_behind'), 'behind'],
    [new ApiError(409, 'x', 'member_dormant'), 'dormant'],
    [new ApiError(409, 'x', 'parent_gone'), 'parentGone'],
    [new ApiError(409, 'x', 'something_new'), 'rejected'],
    [new ApiError(409, 'x'), 'rejected'],
    [new ApiError(400, 'x'), 'rejected'],
    [new ApiError(401, 'x'), 'authRequired'],
    [new ApiError(404, 'x'), 'notFound'],
    [new ApiError(500, 'x'), 'failed'],
    [new ApiError(503, 'x'), 'failed'],
    [new TypeError('Failed to fetch'), 'failed'],
    ['text', 'failed'],
  ])('%s -> %s', (err, kind) => {
    expect(classifyReactionError(err)).toBe(kind)
  })
})
