// Tests for checkGrants with real Ed25519 keys through the same signing
// helpers the app uses. The chain rules themselves are covered in
// lib/crypto/grant-chain.test.ts; this file covers what the runner adds:
// paging, key-history fetching, the anchor pin states, and failure handling.

import { describe, expect, it, vi } from 'vitest'
import type { ListGrantsResponse } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from '@/lib/crypto/ed25519'
import type { GrantRecord } from '@/lib/crypto/grant-chain'
import { roleGrantPayload, trustAnchorPayload } from '@/lib/crypto/group'
import type { StoredAnchorPin } from '@/lib/groups/anchorPin'
import { checkGrants, type GrantCheckDeps } from './runGrantCheck'

const GROUP = '11111111-1111-4111-8111-111111111111'
const CREATOR = 'c0000000-0000-4000-8000-000000000001'
const ALICE = 'a0000000-0000-4000-8000-000000000002'
const BOB = 'b0000000-0000-4000-8000-000000000003'
const EVE = 'e0000000-0000-4000-8000-000000000004'

let n = 0
const sk = (subject: string, day: string) =>
  `GRANT#${subject}#${day}#${(++n).toString(16).padStart(16, '0')}`
const b64 = bytesToBase64

function grant(
  key: SigningKey,
  subject: string,
  role: string,
  grantor: string,
  day: string,
  ref: string,
  sortKey = sk(subject, day),
): GrantRecord {
  const sig = sign(
    key,
    SigningContext.RoleGrant,
    roleGrantPayload(GROUP, subject, role, sortKey, ref),
  )
  return {
    sortKey,
    subjectUserId: subject,
    grantedRole: role,
    grantorUserId: grantor,
    ...(ref ? { grantorGrantRef: ref } : {}),
    signature: b64(sig),
  }
}

function user(id: string, key: SigningKey): UserProjection {
  return {
    userId: id,
    username: id,
    signingPublicKey: b64(key.publicKey),
    wrappingPublicKey: '',
    supersededSigningKeys: [],
  }
}

function world() {
  const creatorKey = generateSigningKey()
  const aliceKey = generateSigningKey()
  const rootSk = sk(CREATOR, '2026-03-01')
  const anchor = {
    creatorUserId: CREATOR,
    creatorSigningPublicKey: b64(creatorKey.publicKey),
    trustAnchorSignature: b64(
      sign(
        creatorKey,
        SigningContext.TrustAnchor,
        trustAnchorPayload(CREATOR, creatorKey.publicKey, GROUP),
      ),
    ),
    rootGrantSortKey: rootSk,
  }
  const root = grant(creatorKey, CREATOR, 'admin', CREATOR, '2026-03-01', '', rootSk)
  const alice = grant(creatorKey, ALICE, 'admin', CREATOR, '2026-03-03', rootSk)
  const bob = grant(aliceKey, BOB, 'ambassador', ALICE, '2026-03-05', alice.sortKey)
  const users = new Map([
    [CREATOR, user(CREATOR, creatorKey)],
    [ALICE, user(ALICE, aliceKey)],
  ])
  return { creatorKey, aliceKey, anchor, root, alice, bob, users }
}

const MEMBERS = [
  { userId: CREATOR, role: 'admin' },
  { userId: ALICE, role: 'admin' },
  { userId: BOB, role: 'ambassador' },
  { userId: EVE, role: 'member' },
]

function deps(
  w: ReturnType<typeof world>,
  over: Partial<GrantCheckDeps> & { pages?: GrantRecord[][] } = {},
): GrantCheckDeps & { pins: Map<string, StoredAnchorPin> } {
  const pages = over.pages ?? [[w.root, w.alice, w.bob]]
  const pins = new Map<string, StoredAnchorPin>()
  return {
    pins,
    listGrants: async (_g, cursor) => {
      const i = cursor === undefined ? 0 : Number(cursor)
      const res: ListGrantsResponse = {
        anchor: w.anchor,
        grants: pages[i]!,
        ...(i + 1 < pages.length && { nextCursor: String(i + 1) }),
      }
      return res
    },
    getUser: async (id) => {
      const u = w.users.get(id)
      if (!u) throw new Error('404')
      return u
    },
    readPin: (g) => pins.get(g) ?? null,
    writePin: (g, p) => {
      pins.set(g, p)
      return true
    },
    ...over,
  }
}

describe('checkGrants', () => {
  it('confirms every role the signed history backs, treating a grantless member as baseline', async () => {
    const w = world()
    const r = await checkGrants(deps(w), GROUP, MEMBERS)
    if (r.state !== 'checked') throw new Error('expected checked')
    for (const m of MEMBERS) expect(r.statuses.get(m.userId)).toEqual({ status: 'verified' })
  })

  it('reads every page of the history and the key history of each distinct signer once', async () => {
    const w = world()
    const getUser = vi.fn(deps(w).getUser)
    const d = deps(w, { pages: [[w.root], [w.alice], [w.bob]], getUser })
    const r = await checkGrants(d, GROUP, MEMBERS)
    expect(r.state === 'checked' && r.statuses.get(BOB)).toEqual({ status: 'verified' })
    // Creator (root + alice grants) and Alice (bob's grant): two lookups.
    expect(getUser).toHaveBeenCalledTimes(2)
  })

  it('flags a role the roster shows that no signed grant backs', async () => {
    const w = world()
    const r = await checkGrants(deps(w), GROUP, [{ userId: EVE, role: 'admin' }])
    expect(r.state === 'checked' && r.statuses.get(EVE)?.status).toBe('unverified')
  })

  it('takes the pin on first sight only when the root verified, and reports first-seen', async () => {
    const w = world()
    const d = deps(w)
    const r = await checkGrants(d, GROUP, MEMBERS)
    expect(r.state === 'checked' && r.anchor).toBe('first-seen')
    expect(d.pins.get(GROUP)).toEqual({
      creatorUserId: CREATOR,
      creatorSigningPublicKey: w.anchor.creatorSigningPublicKey,
    })
  })

  it('does not pin an anchor whose root does not verify', async () => {
    const w = world()
    const d = deps(w, { pages: [[w.alice, w.bob]] })
    const r = await checkGrants(d, GROUP, MEMBERS)
    expect(r.state === 'checked' && r.anchor).toBe('unpinned')
    expect(d.pins.size).toBe(0)
  })

  it('reports unpinned when storage refuses the write', async () => {
    const w = world()
    const r = await checkGrants(deps(w, { writePin: () => false }), GROUP, MEMBERS)
    expect(r.state === 'checked' && r.anchor).toBe('unpinned')
  })

  it('reports pinned when the served anchor matches the earlier pin', async () => {
    const w = world()
    const d = deps(w)
    await checkGrants(d, GROUP, MEMBERS)
    const again = await checkGrants(d, GROUP, MEMBERS)
    expect(again.state === 'checked' && again.anchor).toBe('pinned')
  })

  it('reports changed and confirms nothing when the anchor differs from the pin, even for baseline members', async () => {
    const w = world()
    const d = deps(w)
    d.pins.set(GROUP, {
      creatorUserId: CREATOR,
      creatorSigningPublicKey: b64(generateSigningKey().publicKey),
    })
    const r = await checkGrants(d, GROUP, MEMBERS)
    if (r.state !== 'checked') throw new Error('expected checked')
    expect(r.anchor).toBe('changed')
    for (const m of MEMBERS) expect(r.statuses.get(m.userId)?.status).toBe('unverified')
    // A changed anchor never overwrites the pin.
    expect(d.pins.get(GROUP)?.creatorUserId).toBe(CREATOR)
  })

  it('reports changed when the server serves two different anchors across pages', async () => {
    const w = world()
    const d = deps(w, { pages: [[w.root], [w.alice, w.bob]] })
    const original = d.listGrants
    const listGrants: GrantCheckDeps['listGrants'] = async (g, c) => {
      const res = await original(g, c)
      return c === undefined ? res : { ...res, anchor: { ...res.anchor, creatorUserId: EVE } }
    }
    const r = await checkGrants({ ...d, listGrants }, GROUP, MEMBERS)
    expect(r.state === 'checked' && r.anchor).toBe('changed')
  })

  it('leaves a signer whose key history cannot be read unconfirmed rather than trusting the row', async () => {
    const w = world()
    w.users.delete(ALICE)
    const r = await checkGrants(deps(w), GROUP, MEMBERS)
    if (r.state !== 'checked') throw new Error('expected checked')
    expect(r.statuses.get(BOB)?.status).toBe('unverified')
    expect(r.statuses.get(ALICE)).toEqual({ status: 'verified' })
  })

  it('is unavailable, never throwing, when the grant history cannot be read', async () => {
    const w = world()
    const r = await checkGrants(
      deps(w, {
        listGrants: async () => {
          throw new Error('boom')
        },
      }),
      GROUP,
      MEMBERS,
    )
    expect(r).toEqual({ state: 'unavailable' })
  })

  it('is unavailable when pagination never terminates', async () => {
    const w = world()
    const r = await checkGrants(
      deps(w, { listGrants: async () => ({ anchor: w.anchor, grants: [], nextCursor: 'x' }) }),
      GROUP,
      MEMBERS,
    )
    expect(r).toEqual({ state: 'unavailable' })
  })
})
