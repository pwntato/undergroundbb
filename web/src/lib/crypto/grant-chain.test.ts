// Adversarial tests for verifyGrantChain / checkMemberRole. Every fixture is
// signed with real Ed25519 keys through the same sign/payload functions the
// app uses, so a rejection here is the verifier's decision, not a malformed
// fixture. The mutation notes on each test say which rule it pins.

import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64.js'
import { SigningContext, generateSigningKey, sign, type SigningKey } from './ed25519.js'
import {
  checkMemberRole,
  verifyGrantChain,
  type GrantAnchor,
  type GrantChainInput,
  type GrantRecord,
  type UserKeyHistory,
} from './grant-chain.js'
import { roleGrantPayload, trustAnchorPayload } from './group.js'

const GROUP = '11111111-1111-4111-8111-111111111111'
const CREATOR = 'c0000000-0000-4000-8000-000000000001'
const ALICE = 'a0000000-0000-4000-8000-000000000002'
const BOB = 'b0000000-0000-4000-8000-000000000003'
const EVE = 'e0000000-0000-4000-8000-000000000004'

let counter = 0
function sk(subject: string, day: string): string {
  counter++
  return `GRANT#${subject}#${day}#${counter.toString(16).padStart(16, '0')}`
}

function b64(b: Uint8Array): string {
  return bytesToBase64(b)
}

function grant(
  key: SigningKey,
  subject: string,
  role: string,
  grantor: string,
  day: string,
  ref: string,
  sortKey: string = sk(subject, day),
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
    grantorSigningPublicKey: b64(key.publicKey),
    ...(ref ? { grantorGrantRef: ref } : {}),
    signature: b64(sig),
  }
}

function history(key: SigningKey): UserKeyHistory {
  return { signingPublicKey: b64(key.publicKey), supersededSigningKeys: [] }
}

interface World {
  creatorKey: SigningKey
  aliceKey: SigningKey
  anchor: GrantAnchor
  root: GrantRecord
  aliceAdmin: GrantRecord // day 2026-03-03
  input: GrantChainInput
}

/** creator (root, day 03-01) -> Alice admin (03-03). Alice's key is unrotated. */
function world(): World {
  const creatorKey = generateSigningKey()
  const aliceKey = generateSigningKey()
  const rootKey = sk(CREATOR, '2026-03-01')
  const anchor: GrantAnchor = {
    creatorUserId: CREATOR,
    creatorSigningPublicKey: b64(creatorKey.publicKey),
    trustAnchorSignature: b64(
      sign(
        creatorKey,
        SigningContext.TrustAnchor,
        trustAnchorPayload(CREATOR, creatorKey.publicKey, GROUP),
      ),
    ),
    rootGrantSortKey: rootKey,
  }
  const root = grant(creatorKey, CREATOR, 'admin', CREATOR, '2026-03-01', '', rootKey)
  const aliceAdmin = grant(creatorKey, ALICE, 'admin', CREATOR, '2026-03-03', root.sortKey)
  const input: GrantChainInput = {
    groupId: GROUP,
    anchor,
    grants: [root, aliceAdmin],
    keyHistories: new Map([
      [CREATOR, history(creatorKey)],
      [ALICE, history(aliceKey)],
    ]),
  }
  return { creatorKey, aliceKey, anchor, root, aliceAdmin, input }
}

function pin(a: GrantAnchor) {
  return { creatorUserId: a.creatorUserId, creatorSigningPublicKey: a.creatorSigningPublicKey }
}

function withGrants(w: World, ...extra: GrantRecord[]): GrantChainInput {
  return { ...w.input, grants: [...w.input.grants, ...extra] }
}

function verdictOf(input: GrantChainInput, g: GrantRecord) {
  return verifyGrantChain(input).verdicts.get(g.sortKey)!
}

describe('verifyGrantChain: valid chains', () => {
  it('verifies creator -> Alice -> Bob and reports roles as verified', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'ambassador', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const input = withGrants(w, bob)
    const r = verifyGrantChain(input)
    expect(r.anchorValid).toBe(true)
    for (const g of input.grants) expect(r.verdicts.get(g.sortKey)).toEqual({ valid: true })
    expect(checkMemberRole(r, BOB, 'ambassador')).toEqual({ status: 'verified' })
    expect(checkMemberRole(r, ALICE, 'admin')).toEqual({ status: 'verified' })
    expect(checkMemberRole(r, CREATOR, 'admin')).toEqual({ status: 'verified' })
  })

  it('accepts a grant signed with a since-superseded key the grantor held that day', () => {
    const w = world()
    const newKey = generateSigningKey()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, bob),
      keyHistories: new Map([
        [CREATOR, history(w.creatorKey)],
        [
          ALICE,
          {
            signingPublicKey: b64(newKey.publicKey),
            supersededSigningKeys: [
              {
                publicKey: b64(w.aliceKey.publicKey),
                from: '2026-03-01T00:00:00Z',
                until: '2026-03-10T00:00:00Z',
              },
            ],
          },
        ],
      ]),
    }
    expect(verdictOf(input, bob).valid).toBe(true)
  })

  it('verifies the creator after they rotate keys, because the anchor key is one they held on the root day', () => {
    const w = world()
    const rotated = generateSigningKey()
    const input: GrantChainInput = {
      ...w.input,
      keyHistories: new Map([
        [
          CREATOR,
          {
            signingPublicKey: b64(rotated.publicKey),
            supersededSigningKeys: [
              {
                publicKey: b64(w.creatorKey.publicKey),
                from: '2026-01-01T00:00:00Z',
                until: '2026-04-01T00:00:00Z',
              },
            ],
          },
        ],
        [ALICE, history(w.aliceKey)],
      ]),
    }
    expect(verdictOf(input, w.root).valid).toBe(true)
  })
})

describe('verifyGrantChain: wholesale anchor swap', () => {
  /** The server invents a keypair and a whole chain rooted at a confederate. */
  function swapped(w: World) {
    const evil = generateSigningKey()
    const rootSk = sk(EVE, '2026-03-01')
    const anchor: GrantAnchor = {
      creatorUserId: EVE,
      creatorSigningPublicKey: b64(evil.publicKey),
      trustAnchorSignature: b64(
        sign(evil, SigningContext.TrustAnchor, trustAnchorPayload(EVE, evil.publicKey, GROUP)),
      ),
      rootGrantSortKey: rootSk,
    }
    const root = grant(evil, EVE, 'admin', EVE, '2026-03-01', '', rootSk)
    const bob = grant(evil, BOB, 'admin', EVE, '2026-03-05', rootSk)
    const input: GrantChainInput = {
      groupId: GROUP,
      anchor,
      grants: [root, bob],
      keyHistories: new Map([
        [EVE, history(evil)],
        [CREATOR, history(w.creatorKey)],
      ]),
    }
    return { input, root, bob, anchor, evil }
  }

  it('does not verify a chain rooted at an invented creator with an invented key and self-signed anchor', () => {
    // EVE's own served key history contains the invented key, and the anchor
    // signature is valid under it, so only a pin can reject this.
    const w = world()
    const { input, bob } = swapped(w)
    expect(checkMemberRole(verifyGrantChain(input), BOB, 'admin').status).toBe('verified')
    const pinned = verifyGrantChain({ ...input, pinnedAnchor: pin(w.anchor) })
    expect(pinned.verdicts.get(bob.sortKey)!.valid).toBe(false)
    expect(checkMemberRole(pinned, BOB, 'admin').status).toBe('unverified')
  })

  it('rejects an invented key for the real creator uuid, which the creator never held', () => {
    const w = world()
    const evil = generateSigningKey()
    const anchor: GrantAnchor = {
      creatorUserId: CREATOR,
      creatorSigningPublicKey: b64(evil.publicKey),
      trustAnchorSignature: b64(
        sign(evil, SigningContext.TrustAnchor, trustAnchorPayload(CREATOR, evil.publicKey, GROUP)),
      ),
      rootGrantSortKey: w.root.sortKey,
    }
    const root = grant(evil, CREATOR, 'admin', CREATOR, '2026-03-01', '', w.root.sortKey)
    const bob = grant(evil, BOB, 'admin', CREATOR, '2026-03-05', w.root.sortKey)
    const input: GrantChainInput = { ...w.input, anchor, grants: [root, bob] }
    const r = verifyGrantChain(input)
    expect(r.verdicts.get(root.sortKey)!.reason).toBe(
      'anchor key is not a key the creator held on the root day',
    )
    expect(checkMemberRole(r, BOB, 'admin').status).toBe('unverified')
  })

  it('rejects an anchor key the creator only held after the root day', () => {
    const w = world()
    const later = generateSigningKey()
    const anchor: GrantAnchor = {
      ...w.anchor,
      creatorSigningPublicKey: b64(later.publicKey),
      trustAnchorSignature: b64(
        sign(
          later,
          SigningContext.TrustAnchor,
          trustAnchorPayload(CREATOR, later.publicKey, GROUP),
        ),
      ),
    }
    const root = grant(later, CREATOR, 'admin', CREATOR, '2026-03-01', '', w.root.sortKey)
    const input: GrantChainInput = {
      ...w.input,
      anchor,
      grants: [root],
      keyHistories: new Map([
        [
          CREATOR,
          {
            signingPublicKey: b64(later.publicKey),
            supersededSigningKeys: [
              {
                publicKey: b64(w.creatorKey.publicKey),
                from: '2026-01-01T00:00:00Z',
                until: '2026-04-01T00:00:00Z',
              },
            ],
          },
        ],
      ]),
    }
    expect(verdictOf(input, root).reason).toBe(
      'anchor key is not a key the creator held on the root day',
    )
  })

  it('fails closed when the creator has no key history', () => {
    const w = world()
    const input: GrantChainInput = { ...w.input, keyHistories: new Map() }
    expect(verdictOf(input, w.root).reason).toBe('no key history for creator')
  })

  it('accepts the real chain when it matches the pin', () => {
    const w = world()
    const r = verifyGrantChain({ ...w.input, pinnedAnchor: pin(w.anchor) })
    expect(r.anchorPinned).toBe(true)
    expect(r.verdicts.get(w.aliceAdmin.sortKey)).toEqual({ valid: true })
  })

  it('rejects when the served anchor differs from the pin, in either field', () => {
    const w = world()
    const { anchor: evilAnchor } = swapped(w)
    const wrongUser = verifyGrantChain({
      ...w.input,
      pinnedAnchor: { ...pin(w.anchor), creatorUserId: EVE },
    })
    expect(wrongUser.verdicts.get(w.root.sortKey)!.reason).toBe(
      'anchor does not match the pinned anchor',
    )
    const wrongKey = verifyGrantChain({
      ...w.input,
      pinnedAnchor: {
        ...pin(w.anchor),
        creatorSigningPublicKey: evilAnchor.creatorSigningPublicKey,
      },
    })
    expect(wrongKey.verdicts.get(w.root.sortKey)!.reason).toBe(
      'anchor does not match the pinned anchor',
    )
  })

  it('reports a mismatched pin at the top level, even when the root row is absent', () => {
    const w = world()
    const mismatched = { ...pin(w.anchor), creatorUserId: EVE }
    const withRoot = verifyGrantChain({ ...w.input, pinnedAnchor: mismatched })
    expect(withRoot.anchorPinned).toBe(false)
    expect(withRoot.anchorValid).toBe(false)
    // No root row served: the per-grant comparison never runs, the flags must.
    const noRoot = verifyGrantChain({
      ...w.input,
      grants: [w.aliceAdmin],
      pinnedAnchor: mismatched,
    })
    expect(noRoot.anchorPinned).toBe(false)
    expect(noRoot.anchorValid).toBe(false)
  })

  it('reports a matched pin as pinned and valid', () => {
    const w = world()
    const r = verifyGrantChain({ ...w.input, pinnedAnchor: pin(w.anchor) })
    expect(r.anchorPinned).toBe(true)
    expect(r.anchorValid).toBe(true)
  })

  it('matches a pin on the key bytes, not its base64 spelling', () => {
    const w = world()
    const unpadded = w.anchor.creatorSigningPublicKey.replace(/=+$/, '')
    expect(unpadded).not.toBe(w.anchor.creatorSigningPublicKey)
    const r = verifyGrantChain({
      ...w.input,
      pinnedAnchor: { ...pin(w.anchor), creatorSigningPublicKey: unpadded },
    })
    expect(r.anchorPinned).toBe(true)
    expect(r.verdicts.get(w.root.sortKey)).toEqual({ valid: true })
  })

  it('treats an undecodable pin key as a mismatch', () => {
    const w = world()
    const r = verifyGrantChain({
      ...w.input,
      pinnedAnchor: { ...pin(w.anchor), creatorSigningPublicKey: '!!!' },
    })
    expect(r.anchorPinned).toBe(false)
    expect(r.anchorValid).toBe(false)
  })

  it('reports an unpinned run as such, so callers can say the anchor came from the server', () => {
    expect(verifyGrantChain(world().input).anchorPinned).toBe(false)
  })
})

describe('verifyGrantChain: forgery', () => {
  it('rejects a flipped signature byte', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const bytes = Uint8Array.from(atob(bob.signature), (c) => c.charCodeAt(0))
    bytes[0] = bytes[0]! ^ 1
    const forged = { ...bob, signature: b64(bytes) }
    const v = verdictOf(withGrants(w, forged), forged)
    expect(v.valid).toBe(false)
    expect(v.reason).toMatch(/does not verify under any key/)
  })

  it('ignores the row-supplied grantorSigningPublicKey (server-chosen key)', () => {
    const w = world()
    const evil = generateSigningKey()
    // Eve's key signs a grant "from Alice", and the server writes Eve's key
    // into the hint field. Verifying against the hint would accept it.
    const bob = grant(evil, BOB, 'admin', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    expect(bob.grantorSigningPublicKey).toBe(b64(evil.publicKey))
    expect(verdictOf(withGrants(w, bob), bob).valid).toBe(false)
  })

  it('rejects a signature replayed onto a different sort key (day backdating)', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'admin', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const moved = { ...bob, sortKey: sk(BOB, '2026-03-04') }
    expect(verdictOf(withGrants(w, moved), moved).valid).toBe(false)
  })

  it('rejects a changed role under the original signature', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const upgraded = { ...bob, grantedRole: 'admin' }
    expect(verdictOf(withGrants(w, upgraded), upgraded).valid).toBe(false)
  })

  it('rejects a grant signed for another group', () => {
    const w = world()
    const otherGroup = '22222222-2222-4222-8222-222222222222'
    const sortKey = sk(BOB, '2026-03-05')
    const sig = sign(
      w.aliceKey,
      SigningContext.RoleGrant,
      roleGrantPayload(otherGroup, BOB, 'admin', sortKey, w.aliceAdmin.sortKey),
    )
    const bob: GrantRecord = {
      sortKey,
      subjectUserId: BOB,
      grantedRole: 'admin',
      grantorUserId: ALICE,
      grantorGrantRef: w.aliceAdmin.sortKey,
      signature: b64(sig),
    }
    expect(verdictOf(withGrants(w, bob), bob).valid).toBe(false)
  })

  it('rejects a signature made under the wrong context', () => {
    const w = world()
    const sortKey = sk(BOB, '2026-03-05')
    const sig = sign(
      w.aliceKey,
      SigningContext.Post,
      roleGrantPayload(GROUP, BOB, 'admin', sortKey, w.aliceAdmin.sortKey),
    )
    const bob: GrantRecord = {
      sortKey,
      subjectUserId: BOB,
      grantedRole: 'admin',
      grantorUserId: ALICE,
      grantorGrantRef: w.aliceAdmin.sortKey,
      signature: b64(sig),
    }
    expect(verdictOf(withGrants(w, bob), bob).valid).toBe(false)
  })
})

describe('verifyGrantChain: key-history day resolution', () => {
  function rotatedInput(w: World, oldUntil: string) {
    const newKey = generateSigningKey()
    const histories = new Map([
      [CREATOR, history(w.creatorKey)],
      [
        ALICE,
        {
          signingPublicKey: b64(newKey.publicKey),
          supersededSigningKeys: [
            {
              publicKey: b64(w.aliceKey.publicKey),
              from: '2026-03-01T00:00:00Z',
              until: oldUntil,
            },
          ],
        },
      ],
    ])
    return { newKey, histories }
  }

  it('rejects the old key on a day after it was superseded', () => {
    const w = world()
    const { histories } = rotatedInput(w, '2026-03-04T12:00:00Z')
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    const input = { ...withGrants(w, bob), keyHistories: histories }
    const v = verdictOf(input, bob)
    expect(v.valid).toBe(false)
    expect(v.reason).toMatch(/does not verify under any key/)
  })

  it('rejects the new key on a day before it existed', () => {
    const w = world()
    const { newKey, histories } = rotatedInput(w, '2026-03-04T12:00:00Z')
    // Alice's admin grant moves earlier so 03-03 is not a same-day reject.
    const aliceEarly = grant(w.creatorKey, ALICE, 'admin', CREATOR, '2026-03-02', w.root.sortKey)
    const bob = grant(newKey, BOB, 'member', ALICE, '2026-03-03', aliceEarly.sortKey)
    const input: GrantChainInput = {
      ...w.input,
      grants: [w.root, aliceEarly, bob],
      keyHistories: histories,
    }
    expect(verdictOf(input, bob).reason).toMatch(/does not verify under any key/)
  })

  it('accepts either key on the day of the rotation itself', () => {
    const w = world()
    const { newKey, histories } = rotatedInput(w, '2026-03-05T12:00:00Z')
    const viaOld = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const viaNew = grant(newKey, EVE, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const input = { ...withGrants(w, viaOld, viaNew), keyHistories: histories }
    expect(verdictOf(input, viaOld).valid).toBe(true)
    expect(verdictOf(input, viaNew).valid).toBe(true)
  })

  it('drops a superseded key with no until rather than treating it as unbounded', () => {
    const w = world()
    const newKey = generateSigningKey()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, bob),
      keyHistories: new Map([
        [CREATOR, history(w.creatorKey)],
        [
          ALICE,
          {
            signingPublicKey: b64(newKey.publicKey),
            supersededSigningKeys: [
              { publicKey: b64(w.aliceKey.publicKey), from: '2026-03-01T00:00:00Z' },
            ],
          },
        ],
      ]),
    }
    expect(verdictOf(input, bob).valid).toBe(false)
  })

  it('fails closed when the grantor has no key history', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, bob),
      keyHistories: new Map([[CREATOR, history(w.creatorKey)]]),
    }
    expect(verdictOf(input, bob).reason).toBe('no key history for grantor')
  })
})

describe('verifyGrantChain: broken, cyclic and unrooted chains', () => {
  it('rejects a grantorGrantRef pointing at a grant that does not exist', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', sk(ALICE, '2026-03-02'))
    expect(verdictOf(withGrants(w, bob), bob).reason).toBe(
      "grantorGrantRef is not the grantor's current grant",
    )
  })

  it('rejects a missing grantorGrantRef on a non-root grant', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', '')
    expect(verdictOf(withGrants(w, bob), bob).reason).toBe('missing grantorGrantRef')
  })

  it('rejects a mutually-authorizing pair, which can never reach the root', () => {
    // Alice and Bob each "authorize" the other; neither reaches the root.
    const w = world()
    const aKey = w.aliceKey
    const bKey = generateSigningKey()
    const aSk = sk(ALICE, '2026-03-02')
    const bSk = sk(BOB, '2026-03-02')
    const a = grant(aKey, ALICE, 'admin', BOB, '2026-03-02', bSk, aSk)
    const b = grant(bKey, BOB, 'admin', ALICE, '2026-03-02', aSk, bSk)
    // Grant to Eve on a later day, from Alice, referencing her cyclic grant.
    const eve = grant(aKey, EVE, 'member', ALICE, '2026-03-05', aSk)
    const input: GrantChainInput = {
      groupId: GROUP,
      anchor: w.anchor,
      grants: [w.root, a, b, eve],
      keyHistories: new Map([
        [CREATOR, history(w.creatorKey)],
        [ALICE, history(aKey)],
        [BOB, history(bKey)],
      ]),
    }
    const r = verifyGrantChain(input)
    expect(r.verdicts.get(eve.sortKey)!.valid).toBe(false)
    expect(r.verdicts.get(a.sortKey)!.valid).toBe(false)
    expect(r.verdicts.get(b.sortKey)!.valid).toBe(false)
  })

  it('rejects a root grant whose signature was not made by the anchor key', () => {
    const w = world()
    const evil = generateSigningKey()
    const forgedRoot = grant(evil, CREATOR, 'admin', CREATOR, '2026-03-01', '', w.root.sortKey)
    // The row's hint claims the creator's key; only the signature is wrong.
    const claimed = { ...forgedRoot, grantorSigningPublicKey: b64(w.creatorKey.publicKey) }
    const input: GrantChainInput = { ...w.input, grants: [claimed] }
    expect(verdictOf(input, claimed).reason).toBe(
      'root signature does not verify under the anchor key',
    )
  })

  it('rejects a chain whose root is an attacker-invented self-signed admin', () => {
    // Every signature is real, but the chain roots at a keypair the server
    // invented, not at the stored anchor.
    const w = world()
    const evil = generateSigningKey()
    const evilRootSk = sk(EVE, '2026-03-01')
    const evilRoot = grant(evil, EVE, 'admin', EVE, '2026-03-01', '', evilRootSk)
    const victim = grant(evil, BOB, 'admin', EVE, '2026-03-05', evilRootSk)
    const input: GrantChainInput = {
      ...withGrants(w, evilRoot, victim),
      keyHistories: new Map([
        [CREATOR, history(w.creatorKey)],
        [ALICE, history(w.aliceKey)],
        [EVE, history(evil)],
      ]),
    }
    expect(verdictOf(input, evilRoot).valid).toBe(false)
    expect(verdictOf(input, victim).valid).toBe(false)
    expect(checkMemberRole(verifyGrantChain(input), BOB, 'admin').status).toBe('unverified')
  })

  it('rejects everything when the anchor signature does not verify', () => {
    const w = world()
    const evil = generateSigningKey()
    const input: GrantChainInput = {
      ...w.input,
      anchor: { ...w.anchor, creatorSigningPublicKey: b64(evil.publicKey) },
    }
    const r = verifyGrantChain(input)
    expect(r.anchorValid).toBe(false)
    expect(r.verdicts.get(w.root.sortKey)!.reason).toBe('trust anchor does not verify')
    expect(r.verdicts.get(w.aliceAdmin.sortKey)!.valid).toBe(false)
  })

  it('rejects an anchor signature replayed from another group', () => {
    const w = world()
    const otherGroup = '22222222-2222-4222-8222-222222222222'
    const input: GrantChainInput = { ...w.input, groupId: otherGroup }
    expect(verifyGrantChain(input).anchorValid).toBe(false)
  })

  it('rejects a root grant that is not admin, not self-signed, or has a predecessor', () => {
    const w = world()
    const notAdmin = grant(
      w.creatorKey,
      CREATOR,
      'member',
      CREATOR,
      '2026-03-01',
      '',
      w.root.sortKey,
    )
    expect(verdictOf({ ...w.input, grants: [notAdmin] }, notAdmin).reason).toBe(
      'root grant is not admin',
    )

    // A root address that names Alice as subject, granted by the creator.
    const aliceRootSk = sk(ALICE, '2026-03-01')
    const wrongSubject = grant(w.creatorKey, ALICE, 'admin', CREATOR, '2026-03-01', '', aliceRootSk)
    const aliceRootInput: GrantChainInput = {
      ...w.input,
      anchor: { ...w.anchor, rootGrantSortKey: aliceRootSk },
      grants: [wrongSubject],
    }
    expect(verdictOf(aliceRootInput, wrongSubject).reason).toBe(
      'root grant is not self-signed by the creator',
    )

    const withRef = grant(
      w.creatorKey,
      CREATOR,
      'admin',
      CREATOR,
      '2026-03-01',
      sk(CREATOR, '2026-02-01'),
      w.root.sortKey,
    )
    expect(verdictOf({ ...w.input, grants: [withRef] }, withRef).reason).toBe(
      'root grant has a predecessor',
    )
  })

  it('rejects a non-root self-grant', () => {
    const w = world()
    const self = grant(w.aliceKey, ALICE, 'admin', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    expect(verdictOf(withGrants(w, self), self).reason).toBe('non-root self-grant')
  })

  it('poisons a duplicated sort key instead of picking one', () => {
    const w = world()
    const dup = { ...w.aliceAdmin }
    const input = withGrants(w, dup)
    expect(verdictOf(input, w.aliceAdmin).reason).toBe('duplicate grant sort key')
  })

  it('rejects malformed sort keys and subject mismatches without throwing', () => {
    const w = world()
    const bad = { ...w.aliceAdmin, sortKey: 'GRANT#nope' }
    expect(verdictOf(withGrants(w, bad), bad).reason).toBe('malformed sort key')
    const mismatch = { ...w.aliceAdmin, subjectUserId: BOB }
    expect(verdictOf({ ...w.input, grants: [w.root, mismatch] }, mismatch).reason).toBe(
      'sort key does not match subject',
    )
    const garbage = { ...w.aliceAdmin, signature: '!!!not-base64!!!' }
    expect(verdictOf({ ...w.input, grants: [w.root, garbage] }, garbage).valid).toBe(false)
  })
})

describe('verifyGrantChain: authority and revocation', () => {
  it('rejects a grant signed by an ambassador (only admins change roles)', () => {
    const w = world()
    const ambassador = grant(w.creatorKey, BOB, 'ambassador', CREATOR, '2026-03-02', w.root.sortKey)
    const bobKey = generateSigningKey()
    const eve = grant(bobKey, EVE, 'member', BOB, '2026-03-06', ambassador.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, ambassador, eve),
      keyHistories: new Map([
        [CREATOR, history(w.creatorKey)],
        [ALICE, history(w.aliceKey)],
        [BOB, history(bobKey)],
      ]),
    }
    expect(verdictOf(input, eve).reason).toBe('grantor was not admin on the signing day')
  })

  it('rejects a grant signed after the grantor was demoted, citing the old admin grant', () => {
    const w = world()
    const demote = grant(w.creatorKey, ALICE, 'member', CREATOR, '2026-03-04', w.root.sortKey)
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    const v = verdictOf(withGrants(w, demote, bob), bob)
    expect(v.valid).toBe(false)
    expect(v.reason).toBe("grantorGrantRef is not the grantor's current grant")
  })

  it('rejects a grant signed after demotion even when it cites the demotion row', () => {
    const w = world()
    const demote = grant(w.creatorKey, ALICE, 'member', CREATOR, '2026-03-04', w.root.sortKey)
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-06', demote.sortKey)
    expect(verdictOf(withGrants(w, demote, bob), bob).reason).toBe(
      'grantor was not admin on the signing day',
    )
  })

  it('still accepts a grant Alice signed before her later demotion', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const demote = grant(w.creatorKey, ALICE, 'member', CREATOR, '2026-03-08', w.root.sortKey)
    const input = withGrants(w, bob, demote)
    expect(verdictOf(input, bob).valid).toBe(true)
    expect(checkMemberRole(verifyGrantChain(input), ALICE, 'member')).toEqual({
      status: 'verified',
    })
  })

  it('STRICT same-day: rejects a signature on the day the grantor was demoted', () => {
    const w = world()
    const demote = grant(w.creatorKey, ALICE, 'member', CREATOR, '2026-03-05', w.root.sortKey)
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    expect(verdictOf(withGrants(w, demote, bob), bob).reason).toBe(
      "grantor's role changed on the same UTC day",
    )
  })

  it('STRICT same-day: rejects a signature on the day the grantor was promoted', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-03', w.aliceAdmin.sortKey)
    expect(verdictOf(withGrants(w, bob), bob).reason).toBe(
      "grantor's role changed on the same UTC day",
    )
  })

  it('accepts a signature the day after the promotion', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-04', w.aliceAdmin.sortKey)
    expect(verdictOf(withGrants(w, bob), bob).valid).toBe(true)
  })

  it("rejects when the grantor's latest earlier day holds two grants (order unknowable)", () => {
    const w = world()
    const demote = grant(w.creatorKey, ALICE, 'member', CREATOR, '2026-03-03', w.root.sortKey)
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    expect(verdictOf(withGrants(w, demote, bob), bob).reason).toBe(
      "grantor's current grant is ambiguous (same-day tie)",
    )
  })

  it('rejects a grantor whose only earlier grants are on later days (backdated grant)', () => {
    const w = world()
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-02', w.aliceAdmin.sortKey)
    expect(verdictOf(withGrants(w, bob), bob).reason).toBe(
      'grantor held no grant on the signing day',
    )
  })

  it("rejects when the grantor's own grant does not verify", () => {
    const w = world()
    const evil = generateSigningKey()
    // Alice's admin grant is forged (signed by Eve, not the creator).
    const forged = grant(evil, ALICE, 'admin', CREATOR, '2026-03-03', w.root.sortKey)
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', forged.sortKey)
    const input: GrantChainInput = { ...w.input, grants: [w.root, forged, bob] }
    expect(verdictOf(input, forged).valid).toBe(false)
    expect(verdictOf(input, bob).reason).toBe("grantor's own grant does not verify")
  })
})

describe('checkMemberRole', () => {
  it('treats a member with no grant rows as baseline member', () => {
    const r = verifyGrantChain(world().input)
    expect(checkMemberRole(r, BOB, 'member')).toEqual({ status: 'verified' })
  })

  it('flags a claimed elevated role with no grant behind it', () => {
    const r = verifyGrantChain(world().input)
    expect(checkMemberRole(r, BOB, 'admin').status).toBe('unverified')
    expect(checkMemberRole(r, BOB, 'ambassador').status).toBe('unverified')
  })

  it('flags a roster role that disagrees with the latest grant', () => {
    const w = world()
    const r = verifyGrantChain(w.input)
    const status = checkMemberRole(r, ALICE, 'member')
    expect(status.status).toBe('unverified')
  })

  it('flags a roster role backed only by an invalid grant', () => {
    const w = world()
    const evil = generateSigningKey()
    const forged = grant(evil, BOB, 'admin', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const r = verifyGrantChain(withGrants(w, forged))
    expect(checkMemberRole(r, BOB, 'admin').status).toBe('unverified')
  })

  it("flags a same-day pair as ambiguous instead of picking the server's order", () => {
    const w = world()
    const up = grant(w.creatorKey, BOB, 'admin', CREATOR, '2026-03-05', w.root.sortKey)
    const down = grant(w.creatorKey, BOB, 'member', CREATOR, '2026-03-05', w.root.sortKey)
    const r = verifyGrantChain(withGrants(w, up, down))
    expect(checkMemberRole(r, BOB, 'admin')).toEqual({
      status: 'unverified',
      reason: 'latest grant is ambiguous',
    })
    expect(checkMemberRole(r, BOB, 'member').status).toBe('unverified')
  })

  it('follows a demotion: latest grant wins over an earlier admin grant', () => {
    const w = world()
    const demote = grant(w.creatorKey, ALICE, 'member', CREATOR, '2026-03-08', w.root.sortKey)
    const r = verifyGrantChain(withGrants(w, demote))
    expect(checkMemberRole(r, ALICE, 'member')).toEqual({ status: 'verified' })
    expect(checkMemberRole(r, ALICE, 'admin').status).toBe('unverified')
  })
})

describe('verifyGrantChain: self-demotion on leave', () => {
  // Alice is admin from 03-03 (see world()).
  const demote = (w: World, day: string, key = w.aliceKey) =>
    grant(key, ALICE, 'member', ALICE, day, w.aliceAdmin.sortKey)

  it('verifies an admin demoting themselves and backs the rejoined member role', () => {
    const w = world()
    const d = demote(w, '2026-03-06')
    const r = verifyGrantChain(withGrants(w, d))
    expect(r.verdicts.get(d.sortKey)).toEqual({ valid: true })
    expect(checkMemberRole(r, ALICE, 'member')).toEqual({ status: 'verified' })
    // A roster that still showed her as admin is now the mismatch.
    expect(checkMemberRole(r, ALICE, 'admin').status).toBe('unverified')
  })

  it('verifies an ambassador demoting themselves', () => {
    const w = world()
    const amb = grant(w.aliceKey, BOB, 'ambassador', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const bobKey = generateSigningKey()
    const d = grant(bobKey, BOB, 'member', BOB, '2026-03-07', amb.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, amb, d),
      keyHistories: new Map([...w.input.keyHistories, [BOB, history(bobKey)]]),
    }
    expect(verdictOf(input, d)).toEqual({ valid: true })
    expect(checkMemberRole(verifyGrantChain(input), BOB, 'member')).toEqual({ status: 'verified' })
  })

  it('still verifies the successor Alice promoted the same UTC day she left', () => {
    // Pins the exemption in the same-day rule: without it this is the
    // ordinary promote-then-leave flow being flagged.
    const w = world()
    const bobKey = generateSigningKey()
    const bob = grant(w.aliceKey, BOB, 'admin', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    const d = demote(w, '2026-03-06')
    const input: GrantChainInput = {
      ...withGrants(w, bob, d),
      keyHistories: new Map([...w.input.keyHistories, [BOB, history(bobKey)]]),
    }
    const r = verifyGrantChain(input)
    expect(r.verdicts.get(bob.sortKey)).toEqual({ valid: true })
    expect(r.verdicts.get(d.sortKey)).toEqual({ valid: true })
    expect(checkMemberRole(r, BOB, 'admin')).toEqual({ status: 'verified' })
  })

  it('takes effect the next day: a grant Alice signs after leaving is rejected', () => {
    const w = world()
    const d = demote(w, '2026-03-06')
    const late = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-07', d.sortKey)
    expect(verdictOf(withGrants(w, d, late), late).reason).toBe(
      'grantor was not admin on the signing day',
    )
  })

  it('does not let an INVALID same-day self-demotion excuse the same-day rule', () => {
    const w = world()
    const evil = generateSigningKey()
    const forged = demote(w, '2026-03-06', evil)
    const bob = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    const r = verifyGrantChain(withGrants(w, forged, bob))
    expect(r.verdicts.get(forged.sortKey)?.valid).toBe(false)
    expect(r.verdicts.get(bob.sortKey)?.reason).toBe("grantor's role changed on the same UTC day")
  })

  it('rejects a self-grant to any role but member', () => {
    const w = world()
    const up = grant(w.aliceKey, ALICE, 'ambassador', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    expect(verdictOf(withGrants(w, up), up).reason).toBe('non-root self-grant')
  })

  it("rejects a demotion not signed by the leaver's key", () => {
    const w = world()
    const d = demote(w, '2026-03-06', generateSigningKey())
    expect(verdictOf(withGrants(w, d), d).reason).toBe(
      'signature does not verify under any key the signer held on that day',
    )
  })

  it('rejects a demotion with no ref, a stale ref, or nothing elevated to give up', () => {
    const w = world()
    const noRef = grant(w.aliceKey, ALICE, 'member', ALICE, '2026-03-06', '')
    expect(verdictOf(withGrants(w, noRef), noRef).reason).toBe('missing grantorGrantRef')

    const stale = grant(w.aliceKey, ALICE, 'member', ALICE, '2026-03-06', w.root.sortKey)
    expect(verdictOf(withGrants(w, stale), stale).reason).toBe(
      "grantorGrantRef is not the signer's current grant",
    )

    // Bob is a plain member (granted member), then "demotes" himself.
    const bobKey = generateSigningKey()
    const bobMember = grant(w.aliceKey, BOB, 'member', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const bobD = grant(bobKey, BOB, 'member', BOB, '2026-03-07', bobMember.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, bobMember, bobD),
      keyHistories: new Map([...w.input.keyHistories, [BOB, history(bobKey)]]),
    }
    expect(verdictOf(input, bobD).reason).toBe('signer held no elevated role to give up')
  })

  it('rejects a demotion backed by a grant that does not itself verify', () => {
    const w = world()
    const evil = generateSigningKey()
    const forgedAdmin = grant(evil, BOB, 'admin', ALICE, '2026-03-05', w.aliceAdmin.sortKey)
    const bobKey = generateSigningKey()
    const bobD = grant(bobKey, BOB, 'member', BOB, '2026-03-07', forgedAdmin.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, forgedAdmin, bobD),
      keyHistories: new Map([...w.input.keyHistories, [BOB, history(bobKey)]]),
    }
    expect(verdictOf(input, bobD).reason).toBe("signer's own grant does not verify")
  })

  it('fails safe when the leaver was promoted and left the same day', () => {
    const w = world()
    const promoted = grant(w.creatorKey, BOB, 'admin', CREATOR, '2026-03-06', w.root.sortKey)
    const bobKey = generateSigningKey()
    const d = grant(bobKey, BOB, 'member', BOB, '2026-03-06', promoted.sortKey)
    const input: GrantChainInput = {
      ...withGrants(w, promoted, d),
      keyHistories: new Map([...w.input.keyHistories, [BOB, history(bobKey)]]),
    }
    const r = verifyGrantChain(input)
    expect(r.verdicts.get(d.sortKey)?.reason).toBe("signer's role changed on the same UTC day")
    expect(checkMemberRole(r, BOB, 'member').status).toBe('unverified')
  })
})

describe('verifyGrantChain: removal of an admin (#58)', () => {
  // Alice is admin from 03-03 (see world()). The CREATOR removes her by
  // signing "Alice -> member" under the creator's own admin grant (the root).
  const remove = (w: World, day: string) =>
    grant(w.creatorKey, ALICE, 'member', CREATOR, day, w.root.sortKey)
  const bobFor = (w: World, day: string) =>
    grant(w.aliceKey, BOB, 'admin', ALICE, day, w.aliceAdmin.sortKey)
  const withBob = (w: World, ...extra: GrantRecord[]): GrantChainInput => ({
    ...withGrants(w, ...extra),
    keyHistories: new Map([...w.input.keyHistories, [BOB, history(generateSigningKey())]]),
  })

  it('verifies the remover-signed demotion and backs the removed admin as member', () => {
    const w = world()
    const d = remove(w, '2026-03-06')
    const r = verifyGrantChain(withGrants(w, d))
    expect(r.verdicts.get(d.sortKey)).toEqual({ valid: true })
    expect(checkMemberRole(r, ALICE, 'member')).toEqual({ status: 'verified' })
    expect(checkMemberRole(r, ALICE, 'admin').status).toBe('unverified')
  })

  it('verifies a grant the removed admin signed on an earlier day than the removal', () => {
    const w = world()
    const bob = bobFor(w, '2026-03-05')
    const r = verifyGrantChain(withBob(w, bob, remove(w, '2026-03-06')))
    expect(r.verdicts.get(bob.sortKey)).toEqual({ valid: true })
    expect(checkMemberRole(r, BOB, 'admin')).toEqual({ status: 'verified' })
  })

  it('rejects a grant the removed admin signs the day after the removal', () => {
    const w = world()
    const d = remove(w, '2026-03-06')
    const late = bobFor(w, '2026-03-07')
    expect(verdictOf(withBob(w, d, late), late).reason).toBe(
      "grantorGrantRef is not the grantor's current grant",
    )
  })

  // KNOWN GAP, pinned on purpose. The same-day exemption is for SELF-demotion
  // only. A removed admin's grants dated the SAME UTC day as the removal are
  // rejected, including honest ones signed before the removal: the order
  // within a day is unknowable, and accepting them would let a server
  // colluding with the removed admin store a grant signed AFTER the removal
  // and have it verify, which is exactly what removal exists to prevent.
  // Fails safe (a flag, never a false "verified"). The promoted member stays
  // unverified until a later grant re-establishes them. Do not "fix" this by
  // extending the exemption without a way to order within a day.
  it('flags a grant the removed admin signed the SAME day as the removal (known gap)', () => {
    const w = world()
    const bob = bobFor(w, '2026-03-06')
    const r = verifyGrantChain(withBob(w, bob, remove(w, '2026-03-06')))
    expect(r.verdicts.get(bob.sortKey)).toEqual({
      valid: false,
      reason: "grantor's role changed on the same UTC day",
    })
    expect(checkMemberRole(r, BOB, 'admin').status).toBe('unverified')
    // The removal itself is unaffected.
    expect(checkMemberRole(r, ALICE, 'member')).toEqual({ status: 'verified' })
  })

  it('does not extend the self-demotion exemption to a demotion by someone else', () => {
    // Same shape as the self-demotion promote-then-leave test, with the
    // demotion signed by the creator instead of Alice: the exemption must not
    // apply, or the gap above would be open.
    const w = world()
    const bob = bobFor(w, '2026-03-06')
    const viaSelf = grant(w.aliceKey, ALICE, 'member', ALICE, '2026-03-06', w.aliceAdmin.sortKey)
    expect(verdictOf(withBob(w, bob, viaSelf), bob).valid).toBe(true)
    expect(verdictOf(withBob(w, bob, remove(w, '2026-03-06')), bob).valid).toBe(false)
  })
})
