// Reading one post for the thread page (#318): the same opening and checking as a
// page of the list, so these pin that it is the same, and the failures it can word.
import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, WireLivePost, WirePost } from '@/lib/api/groups'
import type { UserDetail } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from '@/lib/crypto/ed25519'
import { signedPayload } from '@/lib/crypto/payload'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import type { OpenedPost } from '@/lib/crypto/worker-protocol'
import {
  isDeletedPost,
  loadPost,
  makeAuthorResolver,
  type LoadPostDeps,
  type PostView,
} from './runListPosts'

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
  over: { generation?: number; signedGeneration?: number; signedDay?: string } = {},
): WireLivePost {
  counter += 1
  const sortKey = `POST#${day}#${counter.toString(16).padStart(16, '0')}`
  const ciphertext = new Uint8Array(60).fill(counter)
  const generation = over.generation ?? 0
  const payload = signedPayload(
    author,
    GROUP,
    sortKey,
    over.signedGeneration ?? generation,
    over.signedDay ?? day,
    ciphertext,
  )
  return {
    sortKey,
    authorUserId: author,
    generation,
    nonce: b64(new Uint8Array(12)),
    ciphertext: b64(ciphertext),
    signature: b64(sign(key, SigningContext.Post, payload)),
    ...(over.signedDay !== undefined && { signedDay: over.signedDay }),
  }
}

/** A deleted post exactly as the server serves one: every field but the sort key empty. */
function tombstone(day: string): WirePost {
  counter += 1
  return {
    sortKey: `POST#${day}#${counter.toString(16).padStart(16, '0')}`,
    authorUserId: '',
    generation: 0,
    nonce: '',
    ciphertext: '',
    signature: '',
    deleted: true,
  } as unknown as WirePost
}

const opened = (at: string, title = 't'): OpenedPost => ({ kind: 'opened', title, body: 'b', at })

type Mocked = Record<
  'getGroup' | 'getChain' | 'getPost' | 'openPosts' | 'getUserDetail' | 'listPins' | 'pinKeys',
  ReturnType<typeof vi.fn>
>

function depsFor(post: WirePost, open?: () => OpenedPost): LoadPostDeps & Mocked {
  const users: Record<string, UserDetail> = {
    [ME]: detailOf(ME, me, 'me'),
    [ALICE]: detailOf(ALICE, aliceKey, 'alice'),
  }
  return {
    getGroup: vi.fn().mockResolvedValue(DETAIL),
    getChain: vi.fn().mockResolvedValue([]),
    getPost: vi.fn().mockResolvedValue(post),
    openPosts: vi
      .fn()
      .mockImplementation(async () => [open ? open() : opened('2026-10-28T12:00:00.000Z')]),
    getUserDetail: vi.fn().mockImplementation(async (id: string) => users[id]),
    selfUserId: ME,
    ownSigningKey: vi.fn().mockResolvedValue(b64(me.publicKey)),
    listPins: vi.fn().mockResolvedValue([pinOf(ALICE, aliceKey)]),
    pinKeys: vi.fn().mockResolvedValue(undefined),
  }
}

const PID = `${GROUP}#2026-10-28#0000000000000001`

async function load(post: WirePost, open?: () => OpenedPost) {
  const deps = depsFor(post, open)
  const res = await loadPost(deps, makeAuthorResolver(deps), GROUP, PID)
  return { res, deps }
}

describe('loadPost', () => {
  it('opens one post and checks its signature under the author’s anchored keys, as the list does', async () => {
    const hers = wirePost(ALICE, aliceKey, '2026-10-28')
    const { res, deps } = await load(hers)
    if (!res.ok || isDeletedPost(res.post)) throw new Error('expected a live post')
    const post: PostView = res.post
    expect(post).toMatchObject({
      sortKey: hers.sortKey,
      authorUserId: ALICE,
      authorName: 'alice',
      signature: { kind: 'valid' },
      keyAnchor: 'pinned',
      content: { kind: 'opened', title: 't', body: 'b' },
    })
    expect(deps.getPost).toHaveBeenCalledWith(PID)
    expect(deps.openPosts).toHaveBeenCalledTimes(1)
  })

  it('flags a signature that does not verify, and a post that does not open', async () => {
    const forged = wirePost(ALICE, aliceKey, '2026-10-28', { signedGeneration: 9 })
    const bad = await load(forged)
    expect(bad.res).toMatchObject({ ok: true, post: { signature: { kind: 'invalid' } } })
    const sealed = await load(wirePost(ALICE, aliceKey, '2026-10-28'), () => ({
      kind: 'unreadable',
    }))
    expect(sealed.res).toMatchObject({ ok: true, post: { content: { kind: 'unreadable' } } })
  })

  it('checks an edited post over the served signedDay and shows its edit', async () => {
    const edited = wirePost(ALICE, aliceKey, '2026-10-28', { signedDay: '2026-10-29' })
    const { res } = await load(edited, () => ({
      ...opened('2026-10-28T12:00:00.000Z'),
      editedAt: '2026-10-29T08:00:00.000Z',
    }))
    expect(res).toMatchObject({
      ok: true,
      post: {
        signedDay: '2026-10-29',
        signature: { kind: 'valid' },
        content: { editedAt: '2026-10-29T08:00:00.000Z', timeSuspect: false },
      },
    })
  })

  it('shows a deleted post as its place alone, opening and fetching nothing else', async () => {
    const gone = tombstone('2026-10-28')
    const { res, deps } = await load(gone)
    expect(res).toEqual({
      ok: true,
      post: { deleted: true, sortKey: gone.sortKey, day: '2026-10-28' },
    })
    expect(deps.openPosts).not.toHaveBeenCalled()
    expect(deps.getChain).not.toHaveBeenCalled()
    expect(deps.getUserDetail).not.toHaveBeenCalled()
  })

  it('fetches the chain when the post is older than the caller’s key, and says when it cannot', async () => {
    const old = wirePost(ALICE, aliceKey, '2026-10-28', { generation: 0 })
    const deps = depsFor(old)
    deps.getGroup.mockResolvedValue({ ...DETAIL, generation: 2 })
    expect(await loadPost(deps, makeAuthorResolver(deps), GROUP, PID)).toMatchObject({ ok: true })
    expect(deps.getChain).toHaveBeenCalledWith(GROUP, 0, 2)
    deps.getChain.mockResolvedValue(undefined)
    expect(await loadPost(deps, makeAuthorResolver(deps), GROUP, PID)).toEqual({
      ok: false,
      kind: 'chain',
    })
  })

  it('maps each failure to a kind the screen can word', async () => {
    const post = wirePost(ALICE, aliceKey, '2026-10-28')
    const run = async (arrange: (d: ReturnType<typeof depsFor>) => void) => {
      const deps = depsFor(post)
      arrange(deps)
      return loadPost(deps, makeAuthorResolver(deps), GROUP, PID)
    }
    const kind = (r: Awaited<ReturnType<typeof run>>) => (r.ok ? 'ok' : r.kind)
    expect(kind(await run((d) => d.getPost.mockRejectedValue(new ApiError(404, 'gone'))))).toBe(
      'notFound',
    )
    expect(kind(await run((d) => d.getGroup.mockRejectedValue(new ApiError(404, 'gone'))))).toBe(
      'notFound',
    )
    expect(kind(await run((d) => d.getPost.mockRejectedValue(new ApiError(401, 'no'))))).toBe(
      'authRequired',
    )
    expect(kind(await run((d) => d.getPost.mockRejectedValue(new ApiError(500, 'boom'))))).toBe(
      'failed',
    )
    expect(kind(await run((d) => d.getPost.mockRejectedValue(new Error('offline'))))).toBe('failed')
    expect(kind(await run((d) => d.getGroup.mockResolvedValue({ ...DETAIL, role: '' })))).toBe(
      'notFound',
    )
    expect(kind(await run((d) => d.openPosts.mockRejectedValue(new Error('boom'))))).toBe('failed')
    expect(
      kind(await run((d) => d.openPosts.mockRejectedValue(new Error('no live keys cached')))),
    ).toBe('coldKeys')
  })
})
