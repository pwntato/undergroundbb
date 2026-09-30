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

  it('verifies the creator after they rotate keys, because the anchor pins the old key', () => {
    const w = world()
    // The creator's current key is different; the root still verifies under
    // the anchor key, never the creator's key history.
    const rotated = generateSigningKey()
    const input: GrantChainInput = {
      ...w.input,
      keyHistories: new Map([
        [CREATOR, history(rotated)],
        [ALICE, history(w.aliceKey)],
      ]),
    }
    expect(verdictOf(input, w.root).valid).toBe(true)
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
