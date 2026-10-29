import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, WirePost } from '@/lib/api/groups'
import type { UserDetail } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from '@/lib/crypto/ed25519'
import { signedPayload } from '@/lib/crypto/payload'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import type { OpenedPost } from '@/lib/crypto/worker-protocol'
import { loadPostsPage, makeAuthorResolver, type ListPostsDeps } from './runListPosts'

const GROUP = 'a0000000-0000-4000-8000-000000000001'
const ME = 'b0000000-0000-4000-8000-000000000002'
const ALICE = 'c0000000-0000-4000-8000-000000000003'
const b64 = bytesToBase64
const me = generateSigningKey()
const aliceKey = generateSigningKey()
const WRAP = new Uint8Array(32).fill(5)

const WRAPPED = { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' }
const DETAIL = {
  groupId: GROUP,
  role: 'member',
  generation: 0,
  wrappedGroupKey: WRAPPED,
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

function pinOf(id: string, key: SigningKey, signer: SigningKey = me): PinRecord {
  const payload = pinPayload(ME, id, me.publicKey, WRAP, [key.publicKey], 0, '2026-10-01')
  return {
    pinnedUserId: id,
    signingPublicKeys: [b64(key.publicKey)],
    wrappingPublicKey: b64(WRAP),
    pinnerSigningPublicKey: b64(me.publicKey),
    signature: b64(sign(signer, SigningContext.Pin, payload)),
    keyEpoch: 0,
    signedDay: '2026-10-01',
  }
}

let counter = 0
function wirePost(
  author: string,
  key: SigningKey,
  day: string,
  over: { generation?: number; signedGeneration?: number } = {},
): WirePost {
  counter += 1
  const sortKey = `POST#${day}#${counter.toString(16).padStart(16, '0')}`
  const ciphertext = new Uint8Array(60).fill(counter)
  const generation = over.generation ?? 0
  const payload = signedPayload(
    author,
    GROUP,
    sortKey,
    over.signedGeneration ?? generation,
    day,
    ciphertext,
  )
  return {
    sortKey,
    authorUserId: author,
    generation,
    nonce: b64(new Uint8Array(12)),
    ciphertext: b64(ciphertext),
    signature: b64(sign(key, SigningContext.Post, payload)),
  }
}

const opened = (at: string, title = 't'): OpenedPost => ({ kind: 'opened', title, body: 'b', at })

interface World {
  posts: WirePost[]
  nextCursor?: string
  open?: (p: WirePost) => OpenedPost
  users?: Record<string, UserDetail>
  pins?: PinRecord[]
}

type Mocked = Record<
  'getGroup' | 'getChain' | 'listPosts' | 'openPosts' | 'getUserDetail' | 'listPins' | 'pinKeys',
  ReturnType<typeof vi.fn>
>

function depsFor(w: World): ListPostsDeps & Mocked {
  const users = w.users ?? {
    [ME]: detailOf(ME, me, 'me'),
    [ALICE]: detailOf(ALICE, aliceKey, 'alice'),
  }
  return {
    getGroup: vi.fn().mockResolvedValue(DETAIL),
    getChain: vi.fn().mockResolvedValue([]),
    listPosts: vi.fn().mockResolvedValue({
      posts: w.posts,
      ...(w.nextCursor !== undefined && { nextCursor: w.nextCursor }),
    }),
    openPosts: vi.fn().mockImplementation(async (req: { posts: { sortKey: string }[] }) =>
      req.posts.map((rp) => {
        const p = w.posts.find((x) => x.sortKey === rp.sortKey)!
        return w.open ? w.open(p) : opened(`${p.sortKey.slice(5, 15)}T12:00:00.000Z`)
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
  const res = await loadPostsPage(deps, makeAuthorResolver(deps), GROUP, cursor)
  return { res, deps }
}

function views(res: Awaited<ReturnType<typeof load>>['res']) {
  if (!res.ok) throw new Error(`expected a page, got ${res.kind}`)
  return res.posts
}

describe('loadPostsPage', () => {
  it('opens posts, checks the signature under anchored keys, and says how the keys were anchored', async () => {
    const mine = wirePost(ME, me, '2026-10-28')
    const hers = wirePost(ALICE, aliceKey, '2026-10-28')
    const { res } = await load({ posts: [mine, hers] })
    const [a, b] = views(res)
    expect(a).toMatchObject({
      authorName: 'me',
      signature: { kind: 'valid' },
      keyAnchor: 'own',
      content: { kind: 'opened', timeSuspect: false },
    })
    expect(b).toMatchObject({
      authorName: 'alice',
      signature: { kind: 'valid' },
      keyAnchor: 'pinned',
    })
  })

  it('pins an author seen for the first time once, and says so', async () => {
    const p1 = wirePost(ALICE, aliceKey, '2026-10-28')
    const p2 = wirePost(ALICE, aliceKey, '2026-10-28')
    const { res, deps } = await load({ posts: [p1, p2], pins: [] })
    expect(views(res).map((v) => v.keyAnchor)).toEqual(['first-seen', 'first-seen'])
    expect(views(res).every((v) => v.signature.kind === 'valid')).toBe(true)
    expect(deps.pinKeys).toHaveBeenCalledTimes(1)
    expect(deps.pinKeys).toHaveBeenCalledWith(ALICE, [b64(aliceKey.publicKey)], b64(WRAP), 0)
    expect(deps.getUserDetail).toHaveBeenCalledTimes(1)
  })

  it('never re-pins over a changed key and does not check a post under it', async () => {
    const stale = generateSigningKey()
    const post = wirePost(ALICE, aliceKey, '2026-10-28')
    const { res, deps } = await load({ posts: [post], pins: [pinOf(ALICE, stale)] })
    const [v] = views(res)
    expect(v!.signature).toEqual({
      kind: 'unchecked',
      reason: 'their keys changed since you saved them',
    })
    expect(v!.keyAnchor).toBeUndefined()
    expect(deps.pinKeys).not.toHaveBeenCalled()
    // The post itself is still shown: the reader is told it could not vouch for the author.
    expect(v!.content.kind).toBe('opened')
  })

  it('treats a pin that does not verify as unchecked, not as a match', async () => {
    const forged = pinOf(ALICE, aliceKey, generateSigningKey())
    const { res } = await load({ posts: [wirePost(ALICE, aliceKey, '2026-10-28')], pins: [forged] })
    expect(views(res)[0]!.signature).toMatchObject({ kind: 'unchecked' })
  })

  it('is unchecked when a first-seen pin cannot be saved', async () => {
    const deps = depsFor({ posts: [wirePost(ALICE, aliceKey, '2026-10-28')], pins: [] })
    deps.pinKeys.mockRejectedValue(new Error('storage'))
    const res = await loadPostsPage(deps, makeAuthorResolver(deps), GROUP)
    expect(views(res)[0]!.signature).toMatchObject({ kind: 'unchecked' })
  })

  it('flags a signature that does not verify under the anchored keys', async () => {
    const imposter = generateSigningKey()
    const forged = wirePost(ALICE, imposter, '2026-10-28')
    const wrongGeneration = wirePost(ALICE, aliceKey, '2026-10-28', { signedGeneration: 3 })
    const { res } = await load({ posts: [forged, wrongGeneration] })
    expect(views(res).map((v) => v.signature.kind)).toEqual(['invalid', 'invalid'])
  })

  it('flags a post whose decrypted time is not on the sort key’s day, and still checks its signature', async () => {
    const post = wirePost(ALICE, aliceKey, '2026-10-28')
    const { res } = await load({ posts: [post], open: () => opened('2026-10-29T00:00:00.000Z') })
    expect(views(res)[0]).toMatchObject({
      content: { kind: 'opened', timeSuspect: true },
      signature: { kind: 'valid' },
    })
  })

  it('shows a post that does not open as unreadable, without touching its signature verdict', async () => {
    const post = wirePost(ALICE, aliceKey, '2026-10-28')
    const { res } = await load({ posts: [post], open: () => ({ kind: 'unreadable' }) })
    expect(views(res)[0]).toMatchObject({
      content: { kind: 'unreadable' },
      signature: { kind: 'valid' },
    })
  })

  it('is unchecked, never invalid, when an author’s keys cannot be read', async () => {
    const post = wirePost(ALICE, aliceKey, '2026-10-28')
    const { res } = await load({ posts: [post], users: { [ME]: detailOf(ME, me, 'me') } })
    const [v] = views(res)
    expect(v!.signature).toEqual({ kind: 'unchecked', reason: 'their keys could not be read' })
    expect(v!.authorName).toBeNull()
  })

  it('is unchecked when the keys served for you are not the ones you hold', async () => {
    const post = wirePost(ME, me, '2026-10-28')
    const swapped = detailOf(ME, generateSigningKey(), 'me')
    const { res } = await load({ posts: [post], users: { [ME]: swapped } })
    expect(views(res)[0]!.signature).toMatchObject({ kind: 'unchecked' })
  })

  it('is unchecked when your own key or your pins cannot be read', async () => {
    const deps = depsFor({ posts: [wirePost(ALICE, aliceKey, '2026-10-28')] })
    deps.listPins.mockRejectedValue(new Error('down'))
    const res = await loadPostsPage(deps, makeAuthorResolver(deps), GROUP)
    expect(views(res)[0]!.signature).toMatchObject({ kind: 'unchecked' })
  })

  it('orders by day as served, and within a day by the decrypted time, unreadable last', async () => {
    const d2a = wirePost(ALICE, aliceKey, '2026-10-29')
    const d2b = wirePost(ALICE, aliceKey, '2026-10-29')
    const d2c = wirePost(ALICE, aliceKey, '2026-10-29')
    const d1a = wirePost(ALICE, aliceKey, '2026-10-28')
    const d1b = wirePost(ALICE, aliceKey, '2026-10-28')
    const at: Record<string, OpenedPost> = {
      [d2a.sortKey]: opened('2026-10-29T08:00:00.000Z'),
      [d2b.sortKey]: { kind: 'unreadable' },
      [d2c.sortKey]: opened('2026-10-29T20:00:00.000Z'),
      [d1a.sortKey]: opened('2026-10-28T01:00:00.000Z'),
      [d1b.sortKey]: opened('2026-10-28T23:00:00.000Z'),
    }
    const { res } = await load({
      posts: [d2a, d2b, d2c, d1a, d1b],
      open: (p) => at[p.sortKey]!,
    })
    expect(views(res).map((v) => v.sortKey)).toEqual([
      d2c.sortKey,
      d2a.sortKey,
      d2b.sortKey,
      d1b.sortKey,
      d1a.sortKey,
    ])
  })

  it('passes the cursor through and reports the next one', async () => {
    const { res, deps } = await load(
      {
        posts: [wirePost(ALICE, aliceKey, '2026-10-28')],
        nextCursor: 'POST#2026-10-28#0000000000000001',
      },
      'POST#2026-10-29#0000000000000009',
    )
    expect(deps.listPosts).toHaveBeenCalledWith(GROUP, 'POST#2026-10-29#0000000000000009')
    expect(res.ok && res.nextCursor).toBe('POST#2026-10-28#0000000000000001')
  })

  it('is an empty page, without opening anything, when there are no posts', async () => {
    const { res, deps } = await load({ posts: [] })
    expect(res).toEqual({ ok: true, posts: [] })
    expect(deps.openPosts).not.toHaveBeenCalled()
  })

  it('fetches the chain back to the oldest post only when one is older than the caller’s key', async () => {
    const old = wirePost(ALICE, aliceKey, '2026-10-27', { generation: 1 })
    const fresh = wirePost(ALICE, aliceKey, '2026-10-28', { generation: 3 })
    const deps = depsFor({ posts: [fresh, old] })
    deps.getGroup.mockResolvedValue({ ...DETAIL, generation: 3 })
    const link = { generation: 1, wrapped: { nonce: 'n', ciphertext: 'c' } }
    deps.getChain.mockResolvedValue([link])
    await loadPostsPage(deps, makeAuthorResolver(deps), GROUP)
    expect(deps.getChain).toHaveBeenCalledWith(GROUP, 1, 3)
    expect(deps.openPosts.mock.calls[0]![0]).toMatchObject({ generation: 3, chain: [link] })

    const same = depsFor({ posts: [fresh] })
    same.getGroup.mockResolvedValue({ ...DETAIL, generation: 3 })
    await loadPostsPage(same, makeAuthorResolver(same), GROUP)
    expect(same.getChain).not.toHaveBeenCalled()
  })

  it('reports a chain that could not be read, instead of calling every old post unreadable', async () => {
    const old = wirePost(ALICE, aliceKey, '2026-10-27', { generation: 0 })
    const deps = depsFor({ posts: [old] })
    deps.getGroup.mockResolvedValue({ ...DETAIL, generation: 2 })
    deps.getChain.mockResolvedValue(undefined)
    expect(await loadPostsPage(deps, makeAuthorResolver(deps), GROUP)).toEqual({
      ok: false,
      kind: 'chain',
    })
    expect(deps.openPosts).not.toHaveBeenCalled()
  })

  it('maps the failures to a kind the screen can word', async () => {
    const post = wirePost(ALICE, aliceKey, '2026-10-28')
    for (const [err, kind] of [
      [new ApiError(404, 'x'), 'notFound'],
      [new ApiError(401, 'x'), 'authRequired'],
      [new ApiError(500, 'x'), 'failed'],
      [new Error('boom'), 'failed'],
    ] as const) {
      const deps = depsFor({ posts: [post] })
      deps.listPosts.mockRejectedValue(err)
      expect(await loadPostsPage(deps, makeAuthorResolver(deps), GROUP)).toEqual({
        ok: false,
        kind,
      })
    }
    const cold = depsFor({ posts: [post] })
    cold.openPosts.mockRejectedValue(new Error('worker: no live keys cached -- log in'))
    expect(await loadPostsPage(cold, makeAuthorResolver(cold), GROUP)).toEqual({
      ok: false,
      kind: 'coldKeys',
    })
    const broken = depsFor({ posts: [post] })
    broken.openPosts.mockRejectedValue(new Error('unwrap failed'))
    expect(await loadPostsPage(broken, makeAuthorResolver(broken), GROUP)).toEqual({
      ok: false,
      kind: 'failed',
    })
    const gone = depsFor({ posts: [post] })
    gone.getGroup.mockResolvedValue({ ...DETAIL, role: '' })
    expect(await loadPostsPage(gone, makeAuthorResolver(gone), GROUP)).toEqual({
      ok: false,
      kind: 'notFound',
    })
  })

  it('remembers an author across pages through the same resolver', async () => {
    const deps = depsFor({ posts: [wirePost(ALICE, aliceKey, '2026-10-28')], pins: [] })
    const resolve = makeAuthorResolver(deps)
    await loadPostsPage(deps, resolve, GROUP)
    await loadPostsPage(deps, resolve, GROUP)
    expect(deps.getUserDetail).toHaveBeenCalledTimes(1)
    expect(deps.pinKeys).toHaveBeenCalledTimes(1)
  })
})
