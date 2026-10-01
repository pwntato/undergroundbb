// Tests for checkGrants with real Ed25519 keys through the same signing
// helpers the app uses. The chain rules themselves are covered in
// lib/crypto/grant-chain.test.ts; this file covers what the runner adds:
// paging, key-history fetching, the anchor pin states, and failure handling.

import { describe, expect, it, vi } from 'vitest'
import type { ListGrantsResponse } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from '@/lib/crypto/ed25519'
import type { GrantRecord } from '@/lib/crypto/grant-chain'
import { roleGrantPayload, trustAnchorPayload } from '@/lib/crypto/group'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import type { StoredAnchorPin } from '@/lib/groups/anchorPin'
import { checkForView, checkGrants, type GrantCheck, type GrantCheckDeps } from './runGrantCheck'

const GROUP = '11111111-1111-4111-8111-111111111111'
const CREATOR = 'c0000000-0000-4000-8000-000000000001'
const ALICE = 'a0000000-0000-4000-8000-000000000002'
const BOB = 'b0000000-0000-4000-8000-000000000003'
const EVE = 'e0000000-0000-4000-8000-000000000004'
const SELF = 'f0000000-0000-4000-8000-000000000005'
const WRAP = new Uint8Array(32).fill(3)

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
    wrappingPublicKey: b64(WRAP),
    supersededSigningKeys: [],
  }
}

function world() {
  const creatorKey = generateSigningKey()
  const aliceKey = generateSigningKey()
  const selfKey = generateSigningKey()
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
  return { creatorKey, aliceKey, selfKey, anchor, root, alice, bob, users }
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
): GrantCheckDeps & { pins: Map<string, StoredAnchorPin>; keyPins: Map<string, PinRecord> } {
  const pages = over.pages ?? [[w.root, w.alice, w.bob]]
  const pins = new Map<string, StoredAnchorPin>()
  // The fake server side of PIN#: pinKeys signs with the caller's real key
  // exactly as the worker would, and listPins returns what was stored, so a
  // second run evaluates genuinely signed pins.
  const keyPins = new Map<string, PinRecord>()
  return {
    pins,
    keyPins,
    selfUserId: SELF,
    ownSigningKey: async () => b64(w.selfKey.publicKey),
    listPins: async () => [...keyPins.values()],
    pinKeys: async (pinnedUserId, signingPublicKeys, wrappingPublicKey) => {
      const payload = pinPayload(
        SELF,
        pinnedUserId,
        w.selfKey.publicKey,
        base64ToBytes(wrappingPublicKey),
        signingPublicKeys.map((k) => base64ToBytes(k)),
      )
      keyPins.set(pinnedUserId, {
        pinnedUserId,
        signingPublicKeys,
        wrappingPublicKey,
        pinnerSigningPublicKey: b64(w.selfKey.publicKey),
        signature: b64(sign(w.selfKey, SigningContext.Pin, payload)),
      })
    },
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

  it('does not pin an anchor whose root does not verify, and confirms nobody, baseline members included', async () => {
    const w = world()
    // A root signed by a key the creator never held: the server's forged anchor.
    const evil = generateSigningKey()
    const forged = {
      ...w.anchor,
      creatorSigningPublicKey: b64(evil.publicKey),
      trustAnchorSignature: b64(
        sign(evil, SigningContext.TrustAnchor, trustAnchorPayload(CREATOR, evil.publicKey, GROUP)),
      ),
    }
    const forgedRoot = grant(evil, CREATOR, 'admin', CREATOR, '2026-03-01', '', w.root.sortKey)
    const d = deps(w, { pages: [[forgedRoot, w.alice, w.bob]] })
    const listGrants: GrantCheckDeps['listGrants'] = async (g, c) => ({
      ...(await d.listGrants(g, c)),
      anchor: forged,
    })
    const r = await checkGrants({ ...d, listGrants }, GROUP, MEMBERS)
    if (r.state !== 'checked') throw new Error('expected checked')
    expect(r.anchor).toBe('root-unverified')
    expect(d.pins.size).toBe(0)
    for (const m of MEMBERS) expect(r.statuses.get(m.userId)?.status).toBe('unverified')
    expect(r.statuses.get(EVE)).toEqual({
      status: 'unverified',
      reason:
        "the group's root grant could not be checked (anchor key is not a key the creator held on the root day)",
    })
  })

  it('reports root-unverified when the root row is not served at all', async () => {
    const w = world()
    const r = await checkGrants(deps(w, { pages: [[w.alice, w.bob]] }), GROUP, MEMBERS)
    if (r.state !== 'checked') throw new Error('expected checked')
    expect(r.anchor).toBe('root-unverified')
    expect(r.statuses.get(EVE)).toEqual({
      status: 'unverified',
      reason: "the group's root grant could not be checked (not served)",
    })
  })

  it('reports root-unverified, not pinned, when a pinned anchor is served but the creator history cannot be read', async () => {
    const w = world()
    const d = deps(w)
    await checkGrants(d, GROUP, MEMBERS)
    w.users.delete(CREATOR)
    const r = await checkGrants(d, GROUP, MEMBERS)
    if (r.state !== 'checked') throw new Error('expected checked')
    expect(r.anchor).toBe('root-unverified')
    expect(r.statuses.get(EVE)?.status).toBe('unverified')
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

describe('checkGrants key pinning (#63)', () => {
  const checked = (r: GrantCheck) => {
    if (r.state !== 'checked') throw new Error('expected checked')
    return r
  }

  it('pins every grantor on first sight and reports first-seen, then pinned on the next run', async () => {
    const w = world()
    const d = deps(w)
    const first = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(first.keys).toBe('first-seen')
    expect([...d.keyPins.keys()].sort()).toEqual([ALICE, CREATOR].sort())
    const second = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(second.keys).toBe('pinned')
    expect(second.blockedKeyUsers).toEqual([])
    for (const m of MEMBERS) expect(second.statuses.get(m.userId)).toEqual({ status: 'verified' })
  })

  // The attack the whole slice exists for: the server hands out a substituted
  // history for Alice, and a key it holds signs "Bob -> admin" citing Alice's
  // real admin grant. Without the pin check the chain verifies.
  it('blocks a substituted key history for a pinned grantor and confirms nothing that depends on it', async () => {
    const w = world()
    const d = deps(w)
    await checkGrants(d, GROUP, MEMBERS)
    const eve = generateSigningKey()
    w.users.set(ALICE, user(ALICE, eve))
    const forgedBob = grant(eve, BOB, 'ambassador', ALICE, '2026-03-05', w.alice.sortKey)
    const { listGrants } = deps(w, { pages: [[w.root, w.alice, forgedBob]] })
    const r = checked(await checkGrants({ ...d, listGrants }, GROUP, MEMBERS))
    expect(r.keys).toBe('blocked')
    expect(r.blockedKeyUsers).toEqual([ALICE])
    expect(r.statuses.get(BOB)?.status).toBe('unverified')
    // Never re-pinned over the mismatch.
    expect(d.keyPins.get(ALICE)?.signingPublicKeys).toEqual([b64(w.aliceKey.publicKey)])
  })

  it('blocks when the server only ADDS a superseded key to a pinned user', async () => {
    const w = world()
    const d = deps(w)
    await checkGrants(d, GROUP, MEMBERS)
    const extra = generateSigningKey()
    w.users.set(ALICE, {
      ...user(ALICE, w.aliceKey),
      supersededSigningKeys: [
        {
          publicKey: b64(extra.publicKey),
          from: '2026-01-01T00:00:00Z',
          until: '2026-02-01T00:00:00Z',
        },
      ],
    })
    const r = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(r.blockedKeyUsers).toEqual([ALICE])
  })

  it('blocks when the wrapping key alone is swapped', async () => {
    const w = world()
    const d = deps(w)
    await checkGrants(d, GROUP, MEMBERS)
    w.users.set(CREATOR, {
      ...user(CREATOR, w.creatorKey),
      wrappingPublicKey: b64(new Uint8Array(32).fill(4)),
    })
    const r = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(r.blockedKeyUsers).toEqual([CREATOR])
    // The creator's history is withheld, so the root no longer verifies.
    expect(r.anchor).toBe('root-unverified')
  })

  // Mutation: fall back to first-sight when a pin fails to verify -> the
  // server resets any pin by corrupting it and we would re-pin the lie.
  it('treats a corrupted stored pin as blocked, never as first sight, and does not overwrite it', async () => {
    const w = world()
    const d = deps(w)
    await checkGrants(d, GROUP, MEMBERS)
    const pin = d.keyPins.get(ALICE)!
    const badSig = base64ToBytes(pin.signature)
    badSig[0] = badSig[0]! ^ 1
    d.keyPins.set(ALICE, { ...pin, signature: b64(badSig) })
    const r = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(r.blockedKeyUsers).toEqual([ALICE])
    expect(d.keyPins.get(ALICE)?.signature).toBe(b64(badSig))
  })

  it('treats a pin whose recorded signer was rewritten as blocked', async () => {
    const w = world()
    const d = deps(w)
    await checkGrants(d, GROUP, MEMBERS)
    d.keyPins.set(ALICE, {
      ...d.keyPins.get(ALICE)!,
      pinnerSigningPublicKey: b64(generateSigningKey().publicKey),
    })
    expect(checked(await checkGrants(d, GROUP, MEMBERS)).blockedKeyUsers).toEqual([ALICE])
  })

  it('reports unchecked, passing histories through, when the pins cannot be read', async () => {
    const w = world()
    const d = deps(w, {
      listPins: async () => {
        throw new Error('boom')
      },
    })
    const r = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(r.keys).toBe('unchecked')
    expect(d.keyPins.size).toBe(0)
    expect(r.statuses.get(BOB)).toEqual({ status: 'verified' })
  })

  it("reports unchecked when the caller's own key cannot be read (no live keys after a reload)", async () => {
    const w = world()
    const r = checked(
      await checkGrants(
        deps(w, {
          ownSigningKey: async () => {
            throw new Error('no live keys')
          },
        }),
        GROUP,
        MEMBERS,
      ),
    )
    expect(r.keys).toBe('unchecked')
  })

  it("reports unchecked, not pinned, when a grantor's keys cannot be fetched", async () => {
    const w = world()
    const d = deps(w)
    // First run pins everyone, so a clean second run would read "pinned".
    expect(checked(await checkGrants(d, GROUP, MEMBERS)).keys).toBe('first-seen')
    expect(checked(await checkGrants(d, GROUP, MEMBERS)).keys).toBe('pinned')
    const flaky = {
      ...d,
      getUser: async (id: string) => {
        if (id === ALICE) throw new Error('503')
        return d.getUser(id)
      },
    }
    const r = checked(await checkGrants(flaky, GROUP, MEMBERS))
    expect(r.keys).toBe('unchecked')
    expect(r.blockedKeyUsers).toEqual([])
  })

  it('reports unchecked when a new pin cannot be saved, without blocking anyone', async () => {
    const w = world()
    const r = checked(
      await checkGrants(
        deps(w, {
          pinKeys: async () => {
            throw new Error('503')
          },
        }),
        GROUP,
        MEMBERS,
      ),
    )
    expect(r.keys).toBe('unchecked')
    expect(r.blockedKeyUsers).toEqual([])
  })

  it("never pins the caller and checks their own served key against the worker's key", async () => {
    const w = world()
    // SELF is the creator's grantee here: an admin whose grant Bob's chain rests on.
    const selfGrant = grant(w.creatorKey, SELF, 'admin', CREATOR, '2026-03-03', w.root.sortKey)
    const bobBySelf = grant(w.selfKey, BOB, 'ambassador', SELF, '2026-03-05', selfGrant.sortKey)
    w.users.set(SELF, user(SELF, w.selfKey))
    const d = deps(w, { pages: [[w.root, selfGrant, bobBySelf]] })
    const ok = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(d.keyPins.has(SELF)).toBe(false)
    expect(ok.blockedKeyUsers).toEqual([])
    expect(ok.statuses.get(BOB)).toEqual({ status: 'verified' })

    w.users.set(SELF, user(SELF, generateSigningKey()))
    const bad = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(bad.blockedKeyUsers).toEqual([SELF])
    expect(bad.statuses.get(BOB)?.status).toBe('unverified')
  })

  it('blocks a first-sight user whose served keys are malformed rather than pinning them', async () => {
    const w = world()
    w.users.set(ALICE, { ...user(ALICE, w.aliceKey), signingPublicKey: '!!!' })
    const d = deps(w)
    const r = checked(await checkGrants(d, GROUP, MEMBERS))
    expect(r.blockedKeyUsers).toEqual([ALICE])
    expect(d.keyPins.has(ALICE)).toBe(false)
  })
})

describe('checkForView', () => {
  const result: GrantCheck = {
    state: 'checked',
    anchor: 'pinned',
    keys: 'pinned',
    blockedKeyUsers: [],
    statuses: new Map([[BOB, { status: 'unverified', reason: 'stale' } as const]]),
  }
  const viewA = { groupId: 'a' }
  const viewB = { groupId: 'a' } // same content, a reloaded roster: a different view

  it('shows the check only for the exact view it ran against', () => {
    expect(checkForView({ view: viewA, result }, viewA)).toBe(result)
  })

  it('hides a check from a previous roster or another group', () => {
    expect(checkForView({ view: viewA, result }, viewB)).toBeNull()
    expect(checkForView({ view: viewA, result }, { groupId: 'other' })).toBeNull()
  })

  it('shows nothing before any check has run', () => {
    expect(checkForView(null, viewA)).toBeNull()
  })
})
