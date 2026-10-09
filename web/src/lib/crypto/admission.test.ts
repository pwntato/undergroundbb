// Adversarial tests for verifyAdmission (#178). Fixtures are signed with real
// Ed25519 keys through the same payload functions the app uses, over a real
// verified grant chain, so a rejection is the verifier's decision and not a
// malformed fixture. Each test names the rule it pins.

import { describe, expect, it } from 'vitest'
import { verifyAdmission, type AdmissionRecord } from './admission.js'
import { bytesToBase64 } from './base64.js'
import { SigningContext, generateSigningKey, sign, type SigningKey } from './ed25519.js'
import {
  verifyGrantChain,
  type GrantAnchor,
  type GrantChainResult,
  type GrantRecord,
  type UserKeyHistory,
} from './grant-chain.js'
import { admissionPayload, roleGrantPayload, trustAnchorPayload } from './group.js'

const GROUP = '11111111-1111-4111-8111-111111111111'
const CREATOR = 'c0000000-0000-4000-8000-000000000001'
const ALICE = 'a0000000-0000-4000-8000-000000000002'
const MEMBER = 'b0000000-0000-4000-8000-000000000003'

let counter = 0
function sk(subject: string, day: string): string {
  counter++
  return `GRANT#${subject}#${day}#${counter.toString(16).padStart(16, '0')}`
}
const b64 = bytesToBase64

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
  memberSigning: Uint8Array
  memberWrapping: Uint8Array
  root: GrantRecord // creator admin, 2026-03-01
  aliceAdmin: GrantRecord // Alice admin, 2026-03-03
  grants: GrantRecord[]
  chain: () => GrantChainResult
}

function world(extra: (w: Omit<World, 'chain'>) => GrantRecord[] = () => []): World {
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
  const base = {
    creatorKey,
    aliceKey,
    memberSigning: generateSigningKey().publicKey,
    memberWrapping: new Uint8Array(32).fill(7),
    root,
    aliceAdmin,
  }
  const grants = [root, aliceAdmin, ...extra({ ...base, grants: [] })]
  return {
    ...base,
    grants,
    chain: () =>
      verifyGrantChain({
        groupId: GROUP,
        anchor,
        grants,
        keyHistories: new Map([
          [CREATOR, history(creatorKey)],
          [ALICE, history(aliceKey)],
        ]),
      }),
  }
}

interface Admit {
  inviter?: string
  inviterKey?: SigningKey
  ref?: string
  day?: string
  /** Signed group-key generation (default 0). */
  generation?: number
  signedKeys?: { ed?: Uint8Array; x?: Uint8Array }
  signedFor?: { group?: string; invitee?: string; inviteId?: string }
}

/** The admission of w's member, signed by `inviter` (default Alice) unless overridden. */
function admission(w: World, o: Admit = {}): AdmissionRecord {
  const inviter = o.inviter ?? ALICE
  const key = o.inviterKey ?? w.aliceKey
  const ref = o.ref ?? w.aliceAdmin.sortKey
  const day = o.day ?? '2026-03-10'
  const ed = o.signedKeys?.ed ?? w.memberSigning
  const x = o.signedKeys?.x ?? w.memberWrapping
  const inviteId = o.signedFor?.inviteId ?? 'invite-1'
  const payload = admissionPayload(
    o.signedFor?.group ?? GROUP,
    inviter,
    o.signedFor?.invitee ?? MEMBER,
    ed,
    x,
    inviteId,
    ref,
    day,
    o.generation ?? 0,
  )
  return {
    inviteeUserId: MEMBER,
    inviterUserId: inviter,
    inviteId,
    inviteeEd25519PublicKey: b64(ed),
    inviteeX25519PublicKey: b64(x),
    inviterGrantRef: ref,
    day,
    generation: o.generation ?? 0,
    signature: b64(sign(key, SigningContext.Admission, payload)),
  }
}

function check(
  w: World,
  record: AdmissionRecord,
  o: {
    served?: { signing?: Uint8Array[]; wrapping?: Uint8Array }
    inviterHistory?: UserKeyHistory | null
    chain?: GrantChainResult
  } = {},
) {
  return verifyAdmission({
    groupId: GROUP,
    record,
    inviteeSigningKeys: o.served?.signing ?? [w.memberSigning],
    inviteeWrappingKey: b64(o.served?.wrapping ?? w.memberWrapping),
    chain: o.chain ?? w.chain(),
    inviterHistory:
      o.inviterHistory === null ? undefined : (o.inviterHistory ?? history(w.aliceKey)),
  })
}

function rejected(v: ReturnType<typeof check>, why: RegExp) {
  expect(v.ok).toBe(false)
  if (!v.ok) expect(v.reason).toMatch(why)
}

describe('verifyAdmission: valid records', () => {
  it('admits a member invited by a promoted admin', () => {
    const w = world()
    expect(check(w, admission(w))).toEqual({ ok: true })
  })

  it("admits a member invited by the creator under the creator's root grant", () => {
    const w = world()
    const record = admission(w, {
      inviter: CREATOR,
      inviterKey: w.creatorKey,
      ref: w.root.sortKey,
    })
    expect(check(w, record, { inviterHistory: history(w.creatorKey) })).toEqual({ ok: true })
  })

  it('admits on the same day the inviter was granted (create a group and invite on day one)', () => {
    const w = world()
    const record = admission(w, {
      inviter: CREATOR,
      inviterKey: w.creatorKey,
      ref: w.root.sortKey,
      day: '2026-03-01',
    })
    expect(check(w, record, { inviterHistory: history(w.creatorKey) })).toEqual({ ok: true })
  })

  it('admits an ambassador inviter', () => {
    const w = world((b) => [
      grant(
        b.creatorKey,
        MEMBER.replace('3', '5'),
        'ambassador',
        CREATOR,
        '2026-03-04',
        b.root.sortKey,
      ),
    ])
    const amb = MEMBER.replace('3', '5')
    const ambKey = generateSigningKey()
    const ref = w.grants[2]!.sortKey
    const record = admission(w, { inviter: amb, inviterKey: ambKey, ref })
    expect(check(w, record, { inviterHistory: history(ambKey) })).toEqual({ ok: true })
  })

  it('is not undone by a LATER demotion of the inviter: the member was admitted properly', () => {
    const w = world((b) => [
      grant(b.creatorKey, ALICE, 'member', CREATOR, '2026-03-20', b.root.sortKey),
    ])
    expect(check(w, admission(w, { day: '2026-03-10' }))).toEqual({ ok: true })
  })

  it('accepts a signing key the invitee has since superseded (the record names a served key)', () => {
    const w = world()
    const newer = generateSigningKey().publicKey
    expect(check(w, admission(w), { served: { signing: [newer, w.memberSigning] } })).toEqual({
      ok: true,
    })
  })

  it('accepts a record signed under a key the inviter has since rotated away from', () => {
    const w = world()
    const newKey = generateSigningKey()
    const rotated: UserKeyHistory = {
      signingPublicKey: b64(newKey.publicKey),
      supersededSigningKeys: [
        {
          publicKey: b64(w.aliceKey.publicKey),
          from: '2026-03-01T00:00:00Z',
          until: '2026-03-15T00:00:00Z',
        },
      ],
    }
    expect(check(w, admission(w), { inviterHistory: rotated })).toEqual({ ok: true })
  })
})

describe('verifyAdmission: the record must be about this member', () => {
  it('rejects when the admitted signing key is not served for the member (invented account)', () => {
    const w = world()
    const other = generateSigningKey().publicKey
    rejected(check(w, admission(w), { served: { signing: [other] } }), /signing key/)
  })

  it('rejects when the admitted wrapping key differs from the served one (key substitution)', () => {
    const w = world()
    rejected(
      check(w, admission(w), { served: { wrapping: new Uint8Array(32).fill(9) } }),
      /wrapping key/,
    )
  })

  it('rejects a signature made over different keys than the record carries', () => {
    const w = world()
    const record = admission(w, { signedKeys: { ed: generateSigningKey().publicKey } })
    // The record carries the signed (wrong) key, so the served-key check fires first.
    rejected(check(w, record), /signing key/)
    // Keys swapped in after signing: served keys match, the signature does not.
    const tampered = { ...admission(w, { signedKeys: { ed: generateSigningKey().publicKey } }) }
    const forged: AdmissionRecord = { ...tampered, inviteeEd25519PublicKey: b64(w.memberSigning) }
    rejected(check(w, forged), /signature/)
  })

  it.each([
    ['another group', { group: '22222222-2222-4222-8222-222222222222' }],
    ['another invitee', { invitee: 'x0000000-0000-4000-8000-000000000009' }],
  ])('rejects a signature made for %s (replay)', (_name, signedFor) => {
    const w = world()
    rejected(check(w, admission(w, { signedFor })), /signature/)
  })

  it('rejects a changed invite id', () => {
    const w = world()
    const record = { ...admission(w), inviteId: 'invite-2' }
    rejected(check(w, record), /signature/)
  })

  it('rejects a changed day', () => {
    const w = world()
    const record = { ...admission(w), day: '2026-03-11' }
    rejected(check(w, record), /signature/)
  })

  it.each([
    ['inviteeEd25519PublicKey', 'AAAA'],
    ['inviteeX25519PublicKey', '!!!'],
    ['signature', ''],
    ['day', '2026-13-40'],
    ['day', '10/03/2026'],
  ] as const)('rejects a malformed %s without throwing', (field, value) => {
    const w = world()
    rejected(check(w, { ...admission(w), [field]: value }), /malformed/)
  })
})

describe('verifyAdmission: the inviter must have held the role, and the signature must be theirs', () => {
  it('rejects a signature by someone other than the named inviter', () => {
    const w = world()
    rejected(check(w, admission(w, { inviterKey: generateSigningKey() })), /signature/)
  })

  it('rejects when the inviter named a grant that is not on record', () => {
    const w = world()
    rejected(check(w, admission(w, { ref: sk(ALICE, '2026-03-03') })), /not on record/)
  })

  it("rejects a grant that belongs to someone else (Alice cites the creator's root)", () => {
    const w = world()
    rejected(check(w, admission(w, { ref: w.root.sortKey })), /not on record/)
  })

  it('rejects when the cited grant conferred only member', () => {
    const w = world((b) => [
      grant(b.creatorKey, ALICE, 'member', CREATOR, '2026-03-06', b.aliceAdmin.sortKey),
    ])
    const memberGrant = w.grants[2]!
    rejected(check(w, admission(w, { ref: memberGrant.sortKey, day: '2026-03-10' })), /role/)
  })

  it("rejects when the inviter's grant does not itself verify in the chain", () => {
    const w = world()
    const impostor = generateSigningKey()
    const forged = grant(impostor, ALICE, 'admin', CREATOR, '2026-03-04', w.root.sortKey)
    const w2 = world(() => [forged])
    // forged is signed by a key the creator never held, so the chain flags it.
    rejected(check(w2, admission(w2, { ref: forged.sortKey })), /does not verify/)
  })

  it('rejects an admission dated before the inviter was granted', () => {
    const w = world()
    rejected(check(w, admission(w, { day: '2026-03-02' })), /after the admission/)
  })

  it('rejects when the inviter lost the role between the grant and the admission day', () => {
    const w = world((b) => [
      grant(b.creatorKey, ALICE, 'member', CREATOR, '2026-03-06', b.root.sortKey),
    ])
    rejected(check(w, admission(w, { day: '2026-03-10' })), /changed/)
  })

  it('fails closed on a same-day role change (the order within a day is unknowable)', () => {
    const w = world((b) => [
      grant(b.creatorKey, ALICE, 'member', CREATOR, '2026-03-10', b.root.sortKey),
    ])
    rejected(check(w, admission(w, { day: '2026-03-10' })), /changed/)
  })

  it('rejects a second grant on the grant day itself (tie)', () => {
    const w = world((b) => [
      grant(b.creatorKey, ALICE, 'ambassador', CREATOR, '2026-03-03', b.root.sortKey),
    ])
    rejected(check(w, admission(w, { day: '2026-03-10' })), /changed/)
  })

  it('rejects when the inviter has no key history (fails closed)', () => {
    const w = world()
    rejected(check(w, admission(w), { inviterHistory: null }), /keys are not available/)
  })

  it('rejects a signature made with a key the inviter only held AFTER the admission day', () => {
    const w = world()
    const later = generateSigningKey()
    const rotated: UserKeyHistory = {
      signingPublicKey: b64(later.publicKey),
      supersededSigningKeys: [
        {
          publicKey: b64(w.aliceKey.publicKey),
          from: '2026-03-01T00:00:00Z',
          until: '2026-03-08T00:00:00Z',
        },
      ],
    }
    // Signed with the new key but dated before it existed.
    rejected(
      check(w, admission(w, { inviterKey: later, day: '2026-03-05' }), { inviterHistory: rotated }),
      /signature/,
    )
  })
})
