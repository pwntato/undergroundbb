import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, WireComment, WireReaction } from '@/lib/api/groups'
import type { UserDetail } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from '@/lib/crypto/ed25519'
import { signedPayload } from '@/lib/crypto/payload'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import type { OpenedComment, OpenedReaction } from '@/lib/crypto/worker-protocol'
import { commentDepth, loadThreadPage, type LoadThreadDeps } from './runLoadThread'
import { makeAuthorResolver } from './runListPosts'

const GROUP = 'a0000000-0000-4000-8000-000000000001'
const POST_ID = `${GROUP}#2026-10-28#00112233445566ff`
const ME = 'b0000000-0000-4000-8000-000000000002'
const ALICE = 'c0000000-0000-4000-8000-000000000003'
const b64 = bytesToBase64
const me = generateSigningKey()
const aliceKey = generateSigningKey()
const WRAP = new Uint8Array(32).fill(5)
const DAY = '2026-10-29'

const DETAIL = {
  groupId: GROUP,
  role: 'member',
  generation: 0,
  wrappedGroupKey: { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' },
} as unknown as GroupDetail

function detailOf(id: string, key: SigningKey, username: string): UserDetail {
  return {
    userId: id,
    username,
    signingPublicKey: b64(key.publicKey),
    wrappingPublicKey: b64(WRAP),
    supersededSigningKeys: [],
    keyEpoch: 0,
    keyChanges: [],
  }
}

function pinOf(id: string, key: SigningKey): PinRecord {
  const payload = pinPayload(ME, id, me.publicKey, WRAP, [key.publicKey], 0, '2026-10-01')
  return {
    pinnedUserId: id,
    signingPublicKeys: [b64(key.publicKey)],
    wrappingPublicKey: b64(WRAP),
    pinnerSigningPublicKey: b64(me.publicKey),
    signature: b64(sign(me, SigningContext.Pin, payload)),
    keyEpoch: 0,
    signedDay: '2026-10-01',
  }
}

let counter = 0
function wireComment(
  author: string,
  key: SigningKey,
  path: string,
  over: { generation?: number; signedDay?: string; context?: SigningContext } = {},
): WireComment {
  counter += 1
  const ciphertext = new Uint8Array(60).fill(counter)
  const generation = over.generation ?? 0
  const signedDay = over.signedDay ?? DAY
  const payload = signedPayload(author, GROUP, `CMT#${path}`, generation, signedDay, ciphertext)
  return {
    path,
    authorUserId: author,
    generation,
    signedDay,
    nonce: b64(new Uint8Array(12)),
    ciphertext: b64(ciphertext),
    signature: b64(sign(key, over.context ?? SigningContext.Comment, payload)),
  }
}

const opened = (text: string, at = `${DAY}T12:00:00.000Z`): OpenedComment => ({
  kind: 'opened',
  text,
  at,
})

interface World {
  comments: WireComment[]
  reactions?: WireReaction[]
  openReaction?: (x: WireReaction) => OpenedReaction
  nextCursor?: string
  open?: (c: WireComment) => OpenedComment
  pins?: PinRecord[]
}

type Mocked = Record<
  | 'getGroup'
  | 'getChain'
  | 'getThread'
  | 'openComments'
  | 'openReactions'
  | 'getUserDetail'
  | 'listPins'
  | 'pinKeys',
  ReturnType<typeof vi.fn>
>

function depsFor(w: World): LoadThreadDeps & Parameters<typeof makeAuthorResolver>[0] & Mocked {
  const users: Record<string, UserDetail> = {
    [ME]: detailOf(ME, me, 'me'),
    [ALICE]: detailOf(ALICE, aliceKey, 'alice'),
  }
  return {
    getGroup: vi.fn().mockResolvedValue(DETAIL),
    getChain: vi.fn().mockResolvedValue([]),
    getThread: vi.fn().mockResolvedValue({
      comments: w.comments,
      reactions: w.reactions ?? [],
      ...(w.nextCursor !== undefined && { nextCursor: w.nextCursor }),
    }),
    openComments: vi.fn().mockImplementation(async (req: { comments: { path: string }[] }) =>
      req.comments.map((rc) => {
        const c = w.comments.find((x) => x.path === rc.path)!
        return w.open ? w.open(c) : opened(`text of ${c.path}`)
      }),
    ),
    openReactions: vi
      .fn()
      .mockImplementation(async (req: { reactions: { target: string; reactorUserId: string }[] }) =>
        req.reactions.map((rx) => {
          const x = (w.reactions ?? []).find(
            (y) => y.target === rx.target && y.reactorUserId === rx.reactorUserId,
          )!
          return w.openReaction
            ? w.openReaction(x)
            : ({ kind: 'opened', index: 1 } as OpenedReaction)
        }),
      ),
    getUserDetail: vi.fn().mockImplementation(async (id: string) => {
      const u = users[id]
      if (u === undefined) throw new ApiError(404, 'no such user')
      return u
    }),
    selfUserId: ME,
    ownSigningKey: vi.fn().mockResolvedValue(b64(me.publicKey)),
    listPins: vi.fn().mockResolvedValue(w.pins ?? [pinOf(ALICE, aliceKey)]),
    pinKeys: vi.fn().mockResolvedValue(undefined),
  }
}

async function load(w: World, cursor?: string) {
  const deps = depsFor(w)
  const res = await loadThreadPage(deps, makeAuthorResolver(deps), GROUP, POST_ID, cursor)
  return { res, deps }
}

function views(res: Awaited<ReturnType<typeof load>>['res']) {
  if (!res.ok) throw new Error(`expected a page, got ${res.kind}`)
  return res.comments
}

describe('commentDepth', () => {
  it('counts segments of a well-formed path and refuses anything else', () => {
    expect(commentDepth('0001')).toBe(1)
    expect(commentDepth('0003.0001.0002')).toBe(3)
    expect(commentDepth('0001.0001.0001.0001.0001.0001.0001.0001')).toBe(8)
    for (const bad of [
      '',
      '0000',
      '0001.0000',
      '1',
      '0001.',
      '.0001',
      '0001..0002',
      'abcd',
      '0001.0001.0001.0001.0001.0001.0001.0001.0001',
    ]) {
      expect(commentDepth(bad), bad).toBe(0)
    }
  })
})

describe('loadThreadPage', () => {
  it('opens comments, checks each signature under anchored keys, and keeps the served order', async () => {
    const mine = wireComment(ME, me, '0001')
    const theirs = wireComment(ALICE, aliceKey, '0001.0001')
    const { res, deps } = await load({ comments: [mine, theirs] })
    const v = views(res)
    expect(v.map((c) => [c.path, c.depth, c.authorName])).toEqual([
      ['0001', 1, 'me'],
      ['0001.0001', 2, 'alice'],
    ])
    expect(v.map((c) => c.signature.kind)).toEqual(['valid', 'valid'])
    expect(v.map((c) => c.keyAnchor)).toEqual(['own', 'pinned'])
    expect(v[1]!.content).toEqual({
      kind: 'opened',
      text: 'text of 0001.0001',
      at: `${DAY}T12:00:00.000Z`,
      timeSuspect: false,
    })
    // The post and the group are what the worker is asked to open under.
    expect(deps.getThread).toHaveBeenCalledWith(POST_ID, undefined)
    expect(deps.openComments.mock.calls[0]![0]).toMatchObject({ groupId: GROUP, postId: POST_ID })
  })

  it('passes the cursor on and returns the next one', async () => {
    const { res, deps } = await load(
      { comments: [wireComment(ME, me, '0001')], nextCursor: 'c2' },
      'c1',
    )
    expect(deps.getThread).toHaveBeenCalledWith(POST_ID, 'c1')
    expect(res).toMatchObject({ ok: true, nextCursor: 'c2' })
  })

  it('treats an empty page that carries a cursor as "keep going", and opens nothing', async () => {
    const { res, deps } = await load({ comments: [], nextCursor: 'more' })
    expect(res).toEqual({ ok: true, comments: [], reactions: [], nextCursor: 'more' })
    expect(deps.openComments).not.toHaveBeenCalled()
    expect(deps.getChain).not.toHaveBeenCalled()
  })

  it('has no cursor on the last page', async () => {
    const { res } = await load({ comments: [wireComment(ME, me, '0001')] })
    expect(res).toMatchObject({ ok: true })
    expect(res.ok && 'nextCursor' in res).toBe(false)
  })

  it('fails a signature made under another context, by another key, or over another path', async () => {
    const asPost = wireComment(ALICE, aliceKey, '0001', { context: SigningContext.Post })
    const wrongKey = wireComment(ALICE, generateSigningKey(), '0002')
    const moved = { ...wireComment(ALICE, aliceKey, '0003'), path: '0004' }
    const wrongDay = { ...wireComment(ALICE, aliceKey, '0005'), signedDay: '2026-10-30' }
    const { res } = await load({ comments: [asPost, wrongKey, moved, wrongDay] })
    expect(views(res).map((c) => c.signature.kind)).toEqual([
      'invalid',
      'invalid',
      'invalid',
      'invalid',
    ])
  })

  it('shows an unreadable comment as unreadable and still checks its signature', async () => {
    const c = wireComment(ALICE, aliceKey, '0001')
    const { res } = await load({ comments: [c], open: () => ({ kind: 'unreadable' }) })
    expect(views(res)[0]).toMatchObject({
      content: { kind: 'unreadable' },
      signature: { kind: 'valid' },
    })
  })

  it('flags a time that is not on the signed day, and leaves a matching one alone', async () => {
    const a = wireComment(ALICE, aliceKey, '0001')
    const b = wireComment(ALICE, aliceKey, '0002')
    const { res } = await load({
      comments: [a, b],
      open: (c) =>
        opened('x', c.path === '0001' ? '2026-10-01T00:00:00.000Z' : `${DAY}T00:00:00.000Z`),
    })
    const v = views(res)
    expect(v[0]!.content).toMatchObject({ kind: 'opened', timeSuspect: true })
    expect(v[1]!.content).toMatchObject({ kind: 'opened', timeSuspect: false })
  })

  it('shows a malformed path as unreadable with a failed check, never nested', async () => {
    const bad = wireComment(ALICE, aliceKey, '0001.0000')
    const { res } = await load({ comments: [bad] })
    expect(views(res)[0]).toMatchObject({
      depth: 0,
      content: { kind: 'unreadable' },
      signature: { kind: 'invalid' },
    })
  })

  it('does not check an author whose keys do not match the saved pin, and says why', async () => {
    const c = wireComment(ALICE, aliceKey, '0001')
    const pins = [pinOf(ALICE, generateSigningKey())]
    const { res } = await load({ comments: [c], pins })
    expect(views(res)[0]!.signature).toMatchObject({ kind: 'unchecked' })
    expect(views(res)[0]!.keyAnchor).toBeUndefined()
  })

  it('pins an author seen for the first time and says so', async () => {
    const c = wireComment(ALICE, aliceKey, '0001')
    const { res, deps } = await load({ comments: [c], pins: [] })
    expect(views(res)[0]).toMatchObject({ signature: { kind: 'valid' }, keyAnchor: 'first-seen' })
    expect(deps.pinKeys).toHaveBeenCalledTimes(1)
  })

  it('reads each distinct author once', async () => {
    const comments = ['0001', '0002', '0003'].map((p) => wireComment(ALICE, aliceKey, p))
    const { deps } = await load({ comments })
    expect(deps.getUserDetail).toHaveBeenCalledTimes(1)
  })

  it('walks the key chain only when a comment is from an older generation', async () => {
    const old = wireComment(ALICE, aliceKey, '0001', { generation: 0 })
    const deps = depsFor({ comments: [old] })
    deps.getGroup.mockResolvedValue({ ...DETAIL, generation: 2 })
    deps.getChain.mockResolvedValue([{ generation: 0, wrapped: { nonce: 'n', ciphertext: 'c' } }])
    await loadThreadPage(deps, makeAuthorResolver(deps), GROUP, POST_ID)
    expect(deps.getChain).toHaveBeenCalledWith(GROUP, 0, 2)
    expect(deps.openComments.mock.calls[0]![0].chain).toHaveLength(1)
  })

  it('does not ask for the key chain when every comment is from the current generation', async () => {
    const { res, deps } = await load({ comments: [wireComment(ME, me, '0001', { generation: 0 })] })
    expect(res.ok).toBe(true)
    expect(deps.getChain).not.toHaveBeenCalled()
    expect(deps.openComments.mock.calls[0]![0]).not.toHaveProperty('chain')
  })

  it('says not found, and asks for nothing, when the post belongs to another group', async () => {
    const other = 'd0000000-0000-4000-8000-000000000004'
    for (const postId of [`${other}#2026-10-28#00112233445566ff`, 'not-a-post-id', '']) {
      const deps = depsFor({ comments: [wireComment(ME, me, '0001')] })
      const res = await loadThreadPage(deps, makeAuthorResolver(deps), GROUP, postId)
      expect(res, postId).toEqual({ ok: false, kind: 'notFound' })
      expect(deps.getGroup).not.toHaveBeenCalled()
      expect(deps.getThread).not.toHaveBeenCalled()
      expect(deps.openComments).not.toHaveBeenCalled()
    }
  })

  it('reports a chain that could not be read rather than a thread of unreadable comments', async () => {
    const deps = depsFor({ comments: [wireComment(ALICE, aliceKey, '0001', { generation: 0 })] })
    deps.getGroup.mockResolvedValue({ ...DETAIL, generation: 1 })
    deps.getChain.mockResolvedValue(undefined)
    expect(await loadThreadPage(deps, makeAuthorResolver(deps), GROUP, POST_ID)).toEqual({
      ok: false,
      kind: 'chain',
    })
    expect(deps.openComments).not.toHaveBeenCalled()
  })

  it('maps failures to kinds', async () => {
    const run = async (mutate: (d: ReturnType<typeof depsFor>) => void) => {
      const deps = depsFor({ comments: [wireComment(ME, me, '0001')] })
      mutate(deps)
      return loadThreadPage(deps, makeAuthorResolver(deps), GROUP, POST_ID)
    }
    expect(await run((d) => d.getThread.mockRejectedValue(new ApiError(404, 'x')))).toEqual({
      ok: false,
      kind: 'notFound',
    })
    expect(await run((d) => d.getThread.mockRejectedValue(new ApiError(401, 'x')))).toEqual({
      ok: false,
      kind: 'authRequired',
    })
    expect(await run((d) => d.getThread.mockRejectedValue(new Error('boom')))).toEqual({
      ok: false,
      kind: 'failed',
    })
    expect(await run((d) => d.openComments.mockRejectedValue(new Error('boom')))).toEqual({
      ok: false,
      kind: 'failed',
    })
    expect(await run((d) => d.getGroup.mockResolvedValue({ ...DETAIL, role: '' }))).toEqual({
      ok: false,
      kind: 'notFound',
    })
  })
})

let rxCounter = 0
function wireReaction(
  target: string,
  reactor: string,
  over: Partial<WireReaction> = {},
): WireReaction {
  rxCounter += 1
  return {
    target,
    reactorUserId: reactor,
    generation: 0,
    nonce: b64(new Uint8Array(12)),
    ciphertext: b64(new Uint8Array(17).fill(rxCounter)),
    ...over,
  }
}

describe('loadThreadPage reactions (#46)', () => {
  it("opens a page's reactions under the same keys and shows each as its table index", async () => {
    const rx = [wireReaction('0000', ALICE), wireReaction('0001', ME), wireReaction('0001', ALICE)]
    const { res, deps } = await load({
      comments: [wireComment(ME, me, '0001')],
      reactions: rx,
      openReaction: (x) => ({ kind: 'opened', index: x.reactorUserId === ME ? 2 : 5 }),
    })
    expect(res.ok && res.reactions).toEqual([
      { target: '0000', reactorUserId: ALICE, index: 5 },
      { target: '0001', reactorUserId: ME, index: 2 },
      { target: '0001', reactorUserId: ALICE, index: 5 },
    ])
    const req = deps.openReactions.mock.calls[0]![0]
    expect(req).toMatchObject({
      userId: ME,
      groupId: GROUP,
      postId: POST_ID,
      generation: 0,
      wrappedGroupKey: DETAIL.wrappedGroupKey,
    })
    expect(req.reactions).toEqual(rx)
  })

  it('shows a reaction that does not open as unreadable, not as a reaction and not as gone', async () => {
    const { res } = await load({
      comments: [wireComment(ME, me, '0001')],
      reactions: [wireReaction('0001', ALICE), wireReaction('0001', ME)],
      openReaction: (x) =>
        x.reactorUserId === ALICE ? { kind: 'unreadable' } : { kind: 'opened', index: 3 },
    })
    expect(res.ok && res.reactions.map((x) => x.index)).toEqual([null, 3])
  })

  it('does not ask for reactions when the page has none', async () => {
    const { deps } = await load({ comments: [wireComment(ME, me, '0001')] })
    expect(deps.openReactions).not.toHaveBeenCalled()
  })

  it("shows the post's own reactions even when the page has no comments", async () => {
    const { res, deps } = await load({
      comments: [],
      reactions: [wireReaction('0000', ALICE)],
      nextCursor: 'more',
    })
    expect(res).toEqual({
      ok: true,
      comments: [],
      reactions: [{ target: '0000', reactorUserId: ALICE, index: 1 }],
      nextCursor: 'more',
    })
    expect(deps.openComments).not.toHaveBeenCalled()
  })

  it('leaves out a reaction whose target is neither the post nor a comment path', async () => {
    const bad = [
      '0000.0001',
      '0001.0000',
      '1',
      'CMT#0001',
      '',
      '0001.0001.0001.0001.0001.0001.0001.0001.0001',
    ]
    const { res, deps } = await load({
      comments: [wireComment(ME, me, '0001')],
      reactions: [...bad.map((t) => wireReaction(t, ALICE)), wireReaction('0001', ALICE)],
    })
    expect(res.ok && res.reactions.map((x) => x.target)).toEqual(['0001'])
    expect(
      deps.openReactions.mock.calls[0]![0].reactions.map((x: { target: string }) => x.target),
    ).toEqual(['0001'])
  })

  it('walks the key chain for an older reaction even when every comment is current', async () => {
    const world: World = {
      comments: [wireComment(ME, me, '0001', { generation: 2 })],
      reactions: [wireReaction('0001', ALICE, { generation: 0 })],
    }
    const deps = depsFor(world)
    deps.getGroup.mockResolvedValue({ ...DETAIL, generation: 2 })
    deps.getChain.mockResolvedValue([{ generation: 0, wrapped: { nonce: 'n', ciphertext: 'c' } }])
    const res = await loadThreadPage(deps, makeAuthorResolver(deps), GROUP, POST_ID)
    expect(res.ok).toBe(true)
    expect(deps.getChain).toHaveBeenCalledWith(GROUP, 0, 2)
    expect(deps.openReactions.mock.calls[0]![0].chain).toHaveLength(1)
  })

  it('does not walk the chain when comments and reactions are all current', async () => {
    const { deps } = await load({
      comments: [wireComment(ME, me, '0001')],
      reactions: [wireReaction('0001', ALICE)],
    })
    expect(deps.getChain).not.toHaveBeenCalled()
  })

  it('asks for the password when the keys are cold for reactions', async () => {
    const deps = depsFor({
      comments: [wireComment(ME, me, '0001')],
      reactions: [wireReaction('0001', ALICE)],
    })
    deps.openReactions.mockRejectedValue(new Error('no live keys cached'))
    const res = await loadThreadPage(deps, makeAuthorResolver(deps), GROUP, POST_ID)
    expect(res).toEqual({ ok: false, kind: 'coldKeys' })
  })

  it('still shows the comments when only the reactions cannot be opened', async () => {
    const deps = depsFor({
      comments: [wireComment(ME, me, '0001')],
      reactions: [wireReaction('0001', ALICE)],
    })
    deps.openReactions.mockRejectedValue(new Error('boom'))
    const res = await loadThreadPage(deps, makeAuthorResolver(deps), GROUP, POST_ID)
    expect(res.ok && res.comments.map((c) => c.path)).toEqual(['0001'])
    expect(res.ok && res.reactions).toEqual([{ target: '0001', reactorUserId: ALICE, index: null }])
  })
})
