// Tests for the rotation job. The server is an in-memory fake that applies the
// same rules the real one does (all-or-nothing batch, generation checks), so a
// test of "resume after a lost response" exercises the job's own logic against
// realistic state changes rather than canned replies. Pins are signed with real
// keys, so a pin rejection is evaluatePin's decision, not a malformed fixture.

import { describe, expect, it } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, MemberEntry, MemberRole, RewrapEntry } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { generateSigningKey, sign, SigningContext, type SigningKey } from '@/lib/crypto/ed25519'
import type { AdmissionRecord } from '@/lib/crypto/admission'
import type { GrantAnchor, GrantRecord } from '@/lib/crypto/grant-chain'
import {
  admissionPayload,
  roleGrantPayload,
  rotationStartPayload,
  trustAnchorPayload,
} from '@/lib/crypto/group'
import type { StoredAnchorPin } from '@/lib/groups/anchorPin'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import { describeRotation, runRotation, type RotationDeps } from './runRotation'

const ME = 'a0000000-0000-4000-8000-000000000001'
const GROUP = 'g0000000-0000-4000-8000-000000000009'
const b64 = bytesToBase64
const me = generateSigningKey()

interface Person {
  readonly id: string
  readonly signing: SigningKey
  readonly wrapping: Uint8Array
}

let counter = 0
function person(): Person {
  counter++
  const id = `u${String(counter).padStart(7, '0')}-0000-4000-8000-000000000000`
  return { id, signing: generateSigningKey(), wrapping: new Uint8Array(32).fill(counter % 250) }
}

function served(p: Person): UserProjection {
  return {
    userId: p.id,
    username: p.id,
    signingPublicKey: b64(p.signing.publicKey),
    wrappingPublicKey: b64(p.wrapping),
    supersededSigningKeys: [],
  }
}

function pinFor(p: Person, overrideWrapping?: Uint8Array): PinRecord {
  const wrapping = overrideWrapping ?? p.wrapping
  const payload = pinPayload(ME, p.id, me.publicKey, wrapping, [p.signing.publicKey])
  return {
    pinnedUserId: p.id,
    signingPublicKeys: [b64(p.signing.publicKey)],
    wrappingPublicKey: b64(wrapping),
    pinnerSigningPublicKey: b64(me.publicKey),
    signature: b64(sign(me, SigningContext.Pin, payload)),
  }
}

type Marker = NonNullable<GroupDetail['rotation']>

const REMOVED = 'r0000000-0000-4000-8000-000000000042'

/**
 * A rotation marker as the server serves one after a signed removal (#178):
 * `signer` (default: the caller) names `removed` for `generation`. Overrides
 * model a marker that was tampered with or predates signing.
 */
function startMarker(
  generation: number,
  o: {
    startedBy?: string
    signer?: SigningKey
    removed?: string
    signedFor?: { removed?: string; generation?: number }
    unsigned?: boolean
  } = {},
): Marker {
  const startedBy = o.startedBy ?? ME
  const removed = o.removed ?? REMOVED
  const base = { generation, startedAt: 't', startedBy }
  if (o.unsigned) return base
  const payload = rotationStartPayload(
    GROUP,
    startedBy,
    o.signedFor?.removed ?? removed,
    o.signedFor?.generation ?? generation,
  )
  return {
    ...base,
    removedUserId: removed,
    startSignature: b64(sign(o.signer ?? me, SigningContext.RotationStart, payload)),
  }
}

const ROOT_DAY = '2026-03-01'
const ADMIT_DAY = '2026-03-10'
const ROOT_REF = `GRANT#${ME}#${ROOT_DAY}#0000000000000001`

/** A person whose id can appear in a GRANT# address (hex), for an inviter other than the creator. */
function inviterPerson(): Person {
  counter++
  const id = `f${String(counter).padStart(7, '0')}-0000-4000-8000-000000000000`
  return { id, signing: generateSigningKey(), wrapping: new Uint8Array(32).fill(counter % 250) }
}

/** An admission of `p` signed by `inviter` under `ref` and `day`, as the server stores one. */
function admissionOf(
  p: Person,
  o: {
    inviter?: string
    key?: SigningKey
    ref?: string
    day?: string
    inviteId?: string
    /** Sign over these keys instead of p's (the record then carries them). */
    keys?: { ed?: Uint8Array; x?: Uint8Array }
  } = {},
): AdmissionRecord {
  const inviter = o.inviter ?? ME
  const ed = o.keys?.ed ?? p.signing.publicKey
  const x = o.keys?.x ?? p.wrapping
  const ref = o.ref ?? ROOT_REF
  const day = o.day ?? ADMIT_DAY
  const inviteId = o.inviteId ?? `invite-${p.id}`
  const payload = admissionPayload(GROUP, inviter, p.id, ed, x, inviteId, ref, day)
  return {
    inviteeUserId: p.id,
    inviterUserId: inviter,
    inviteId,
    inviteeEd25519PublicKey: b64(ed),
    inviteeX25519PublicKey: b64(x),
    inviterGrantRef: ref,
    day,
    signature: b64(sign(o.key ?? me, SigningContext.Admission, payload)),
  }
}

interface Row {
  person: Person
  role: MemberRole
  generation: number
}

class Fake {
  members = new Map<string, Row>()
  marker: Marker | undefined = startMarker(1)
  ownGeneration = 1
  role: GroupDetail['role'] = 'admin'
  visibility: GroupDetail['visibility'] = 'private'
  pins = new Map<string, PinRecord>()
  pinKeysError: Error | undefined
  listPinsError: Error | undefined

  // The group's signed history: ME created it, so ME's root grant anchors the
  // chain, and every member `add`ed is admitted by ME unless a test says not.
  anchor: GrantAnchor = {
    creatorUserId: ME,
    creatorSigningPublicKey: b64(me.publicKey),
    trustAnchorSignature: b64(
      sign(me, SigningContext.TrustAnchor, trustAnchorPayload(ME, me.publicKey, GROUP)),
    ),
    rootGrantSortKey: ROOT_REF,
  }
  grants: GrantRecord[] = [
    {
      sortKey: ROOT_REF,
      subjectUserId: ME,
      grantedRole: 'admin',
      grantorUserId: ME,
      signature: b64(
        sign(me, SigningContext.RoleGrant, roleGrantPayload(GROUP, ME, 'admin', ROOT_REF, '')),
      ),
    },
  ]
  admissions = new Map<string, AdmissionRecord>()
  anchorPin: StoredAnchorPin | null = null
  listAdmissionsError: Error | undefined
  admissionReads = 0

  // call logs
  userReads: string[][] = []
  rewrapBatches: { generation: number; users: string[] }[] = []
  completed: number[] = []
  pinned: string[] = []
  cryptoRecipients: string[][] = []
  // hooks run before the Nth server call of a kind; may mutate state or throw
  onRewrap: ((n: number) => void)[] = []
  onComplete: ((n: number) => void)[] = []

  constructor() {
    this.members.set(ME, {
      person: { id: ME, signing: me, wrapping: new Uint8Array(32) },
      role: 'admin',
      generation: 1,
    })
  }

  add(
    p: Person,
    role: MemberRole = 'member',
    generation = 0,
    pin: PinRecord | null | 'auto' = 'auto',
    admission: AdmissionRecord | null | 'auto' = 'auto',
  ): Person {
    this.members.set(p.id, { person: p, role, generation })
    if (admission === 'auto') this.admissions.set(p.id, admissionOf(p))
    else if (admission !== null) this.admissions.set(p.id, admission)
    if (pin === 'auto') this.pins.set(p.id, pinFor(p))
    else if (pin !== null) this.pins.set(p.id, pin)
    return p
  }

  /**
   * Makes the caller an admin the creator promoted, instead of the creator, so
   * the creator is a listed member with no admission of their own and the
   * caller's invitations rest on a promoted admin's grant. Returns the creator
   * and the caller's grant address.
   */
  promoted(): { creator: Person; myGrant: GrantRecord; creatorKey: SigningKey } {
    const creator = inviterPerson()
    const creatorKey = creator.signing
    const rootRef = `GRANT#${creator.id}#${ROOT_DAY}#0000000000000002`
    this.anchor = {
      creatorUserId: creator.id,
      creatorSigningPublicKey: b64(creatorKey.publicKey),
      trustAnchorSignature: b64(
        sign(
          creatorKey,
          SigningContext.TrustAnchor,
          trustAnchorPayload(creator.id, creatorKey.publicKey, GROUP),
        ),
      ),
      rootGrantSortKey: rootRef,
    }
    const rootGrant: GrantRecord = {
      sortKey: rootRef,
      subjectUserId: creator.id,
      grantedRole: 'admin',
      grantorUserId: creator.id,
      signature: b64(
        sign(
          creatorKey,
          SigningContext.RoleGrant,
          roleGrantPayload(GROUP, creator.id, 'admin', rootRef, ''),
        ),
      ),
    }
    const myRef = `GRANT#${ME}#2026-03-03#0000000000000003`
    const myGrant: GrantRecord = {
      sortKey: myRef,
      subjectUserId: ME,
      grantedRole: 'admin',
      grantorUserId: creator.id,
      grantorGrantRef: rootRef,
      signature: b64(
        sign(
          creatorKey,
          SigningContext.RoleGrant,
          roleGrantPayload(GROUP, ME, 'admin', myRef, rootRef),
        ),
      ),
    }
    this.grants = [rootGrant, myGrant]
    // The creator is a member too, behind like the rest, with no admission.
    this.add(creator, 'admin', 0, 'auto', null)
    return { creator, myGrant, creatorKey }
  }

  gen(p: Person): number {
    return this.members.get(p.id)!.generation
  }

  deps(): RotationDeps {
    let rewrapN = 0
    let completeN = 0
    return {
      selfUserId: ME,
      getGroup: async () =>
        ({
          groupId: GROUP,
          visibility: this.visibility,
          role: this.role,
          generation: this.ownGeneration,
          nameGeneration: 0,
          revocationMode: 'rotating',
          expirationDays: 0,
          version: 0,
          wrappedGroupKey: { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' },
          ...(this.marker ? { rotation: this.marker } : {}),
        }) as GroupDetail,
      listAllMembers: async () =>
        [...this.members.values()].map((r): MemberEntry => ({
          userId: r.person.id,
          role: r.role,
          generation: r.generation,
        })),
      getUsers: async (ids) => {
        this.userReads.push([...ids])
        return new Map(
          ids.flatMap((id) => {
            const r = this.members.get(id)
            return r ? [[id, served(r.person)] as const] : []
          }),
        )
      },
      listGrants: async () => ({ anchor: this.anchor, grants: this.grants }),
      listDesignations: async () => ({ designations: [] }),
      listAdmissions: async () => {
        this.admissionReads++
        if (this.listAdmissionsError) throw this.listAdmissionsError
        return { admissions: [...this.admissions.values()] }
      },
      readPin: () => this.anchorPin,
      writePin: (_g, pin) => {
        this.anchorPin = pin
        return true
      },
      ownSigningKey: async () => b64(me.publicKey),
      listPins: async () => {
        if (this.listPinsError) throw this.listPinsError
        return [...this.pins.values()]
      },
      pinKeys: async (id, _keys, wrapping) => {
        if (this.pinKeysError) throw this.pinKeysError
        this.pinned.push(id)
        this.pins.set(
          id,
          pinFor(this.members.get(id)!.person, new Uint8Array(Buffer.from(wrapping, 'base64'))),
        )
      },
      rewrapCrypto: async (req) => {
        this.cryptoRecipients.push(req.recipients.map((r) => r.userId))
        // The key wrapped to must be the one that was pin-checked.
        for (const r of req.recipients) {
          expect(r.x25519PublicKey).toBe(b64(this.members.get(r.userId)!.person.wrapping))
        }
        return {
          wraps: req.recipients.map((r) => ({
            userId: r.userId,
            wrappedKey: { ephemeralPub: 'e', nonce: 'n', ciphertext: `for-${r.userId}` },
          })),
        }
      },
      rewrapMembers: async (_g, req) => {
        rewrapN++
        this.onRewrap[rewrapN - 1]?.(rewrapN)
        const users = req.wraps.map((w: RewrapEntry) => w.userId)
        this.rewrapBatches.push({ generation: req.generation, users })
        // The server's two modes: with a marker it must name this generation and
        // members at or behind it are accepted (retry-safe); with none this is a
        // catch-up and members must be STRICTLY behind.
        if (this.marker && this.marker.generation !== req.generation) {
          throw new ApiError(409, 'no matching rotation', 'rotation_not_active')
        }
        // all-or-nothing, like the server
        for (const u of users) {
          const row = this.members.get(u)
          const ok =
            row &&
            (this.marker ? row.generation <= req.generation : row.generation < req.generation)
          if (!ok) {
            throw new ApiError(409, 'member changed', 'member_changed')
          }
        }
        for (const u of users) this.members.get(u)!.generation = req.generation
      },
      completeRotation: async (_g, generation) => {
        completeN++
        this.onComplete[completeN - 1]?.(completeN)
        if (!this.marker) throw new ApiError(409, 'not active', 'rotation_not_active')
        for (const r of this.members.values()) {
          if (r.generation < generation) throw new ApiError(409, 'behind', 'members_behind')
        }
        this.completed.push(generation)
        this.marker = undefined
      },
    }
  }
}

describe('runRotation', () => {
  it('re-wraps every member who is behind, admins first, then completes', async () => {
    const f = new Fake()
    const carol = f.add(person())
    const eve = f.add(person(), 'admin')
    const dave = f.add(person())

    const out = await runRotation(f.deps(), GROUP)

    expect(out).toEqual({ status: 'completed', rewrapped: 3 })
    expect(f.rewrapBatches).toHaveLength(1)
    expect(f.rewrapBatches[0]!.generation).toBe(1)
    // The other admin is first, so any re-wrapped admin can resume.
    expect(f.rewrapBatches[0]!.users[0]).toBe(eve.id)
    expect(new Set(f.rewrapBatches[0]!.users)).toEqual(new Set([eve.id, carol.id, dave.id]))
    expect(f.completed).toEqual([1])
    expect([carol, dave, eve].map((p) => f.gen(p))).toEqual([1, 1, 1])
  })

  it('never wraps to the caller', async () => {
    const f = new Fake()
    f.add(person())
    await runRotation(f.deps(), GROUP)
    expect(f.rewrapBatches.flatMap((b) => b.users)).not.toContain(ME)
  })

  it('sends batches of at most 25', async () => {
    const f = new Fake()
    for (let i = 0; i < 60; i++) f.add(person())
    const out = await runRotation(f.deps(), GROUP)
    expect(out).toEqual({ status: 'completed', rewrapped: 60 })
    expect(f.rewrapBatches.map((b) => b.users.length)).toEqual([25, 25, 10])
  })

  it('re-wraps only members who are behind (resume skips those already moved)', async () => {
    const f = new Fake()
    const done = f.add(person(), 'admin', 1)
    const todo = f.add(person(), 'member', 0)
    const out = await runRotation(f.deps(), GROUP)
    expect(out).toEqual({ status: 'completed', rewrapped: 1 })
    expect(f.rewrapBatches.flatMap((b) => b.users)).toEqual([todo.id])
    expect(f.rewrapBatches.flatMap((b) => b.users)).not.toContain(done.id)
  })

  it('resumes after a lost response: state, not a cursor, decides what is left', async () => {
    const f = new Fake()
    const people = [f.add(person()), f.add(person()), f.add(person())]
    // The first batch lands on the server but the response is lost.
    const deps = f.deps()
    let first = true
    const lossy: RotationDeps = {
      ...deps,
      rewrapMembers: async (g, req) => {
        await deps.rewrapMembers(g, req)
        if (first) {
          first = false
          throw new TypeError('network error')
        }
      },
    }
    const run1 = await runRotation(lossy, GROUP)
    expect(run1.status).toBe('incomplete')
    expect(f.marker).toBeDefined()

    // A fresh run finds nobody behind (the batch did land) and just completes.
    f.rewrapBatches = []
    const run2 = await runRotation(f.deps(), GROUP)
    expect(run2).toEqual({ status: 'completed', rewrapped: 0 })
    expect(f.rewrapBatches).toHaveLength(0)
    expect(people.map((p) => f.gen(p))).toEqual([1, 1, 1])
  })

  it('re-lists and retries when a member left mid-batch (member_changed)', async () => {
    const f = new Fake()
    const leaver = f.add(person())
    const stay = f.add(person())
    f.onRewrap[0] = () => {
      f.members.delete(leaver.id) // leaves between the listing and the write
    }
    const out = await runRotation(f.deps(), GROUP)
    expect(out).toEqual({ status: 'completed', rewrapped: 1 })
    expect(f.gen(stay)).toBe(1)
  })

  it('completes again after a new behind member appears before completion', async () => {
    const f = new Fake()
    f.add(person())
    const late = person()
    f.onComplete[0] = () => {
      f.add(late) // joins one generation behind just before the first completion
    }
    const out = await runRotation(f.deps(), GROUP)
    expect(out).toEqual({ status: 'completed', rewrapped: 2 })
    expect(f.gen(late)).toBe(1)
    expect(f.completed).toEqual([1])
  })

  it('treats rotation_not_active at completion as done', async () => {
    const f = new Fake()
    f.add(person(), 'member', 1) // nobody behind; another admin finished it first
    f.marker = startMarker(1)
    const deps = f.deps()
    const out = await runRotation(
      {
        ...deps,
        completeRotation: async () => {
          throw new ApiError(409, 'not active', 'rotation_not_active')
        },
      },
      GROUP,
    )
    expect(out).toEqual({ status: 'completed', rewrapped: 0 })
  })

  it('starts over once when the rotation is superseded under a re-wrap, and does not loop', async () => {
    const f = new Fake()
    f.add(person())
    f.onRewrap[0] = () => {
      f.marker = startMarker(2) // a newer rotation began meanwhile
    }
    const deps = f.deps()
    let reads = 0
    const out = await runRotation(
      {
        ...deps,
        getGroup: async (g) => {
          reads++
          return deps.getGroup(g)
        },
      },
      GROUP,
    )
    // One restart (two reads), then the caller is behind the new rotation.
    expect(reads).toBe(2)
    expect(out.status).toBe('cannot-resume')
  })

  it('keeps the re-wrapped count across a restart', async () => {
    const f = new Fake()
    for (let i = 0; i < 26; i++) f.add(person())
    f.onRewrap[1] = () => {
      f.marker = startMarker(2) // superseded after the first batch of 25 landed
      f.ownGeneration = 2
      f.members.get(ME)!.generation = 2
    }
    const out = await runRotation(f.deps(), GROUP)
    expect(out).toEqual({ status: 'completed', rewrapped: 25 + 26 })
  })

  describe('pin checks (fail closed)', () => {
    it('never wraps to a member whose served key mismatches their pin, and does not complete', async () => {
      const f = new Fake()
      const ok = f.add(person())
      const swapped = person()
      // pinned wrapping key differs from what the server now serves
      f.add(swapped, 'member', 0, pinFor(swapped, new Uint8Array(32).fill(250)))

      const out = await runRotation(f.deps(), GROUP)

      expect(out).toEqual({ status: 'blocked', blocked: [swapped.id], rewrapped: 1 })
      expect(f.cryptoRecipients.flat()).toEqual([ok.id])
      expect(f.gen(swapped)).toBe(0)
      expect(f.completed).toEqual([])
      expect(f.pinned).toEqual([]) // never re-pins over a mismatch
    })

    it('re-reads pins every pass: a retry never re-pins over a key pinned earlier in the run', async () => {
      const f = new Fake()
      const x = f.add(person(), 'member', 0, null) // first-sight
      const leaver = f.add(person())
      f.onRewrap[0] = () => {
        f.members.delete(leaver.id) // forces member_changed on the batch
        // the server now serves a different wrapping key for x
        f.members.get(x.id)!.person = { ...x, wrapping: new Uint8Array(32).fill(251) }
        // An admission for the new key too, so this reaches the PIN check
        // (a substituted key with no admission is refused earlier, below).
        f.admissions.set(x.id, admissionOf(x, { keys: { x: new Uint8Array(32).fill(251) } }))
      }
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'blocked', blocked: [x.id], rewrapped: 0 })
      expect(f.pinned).toEqual([x.id]) // pinned once, never re-pinned
      expect(f.gen(x)).toBe(0)
      expect(f.completed).toEqual([])
    })

    it('treats a pin with a bad signature as blocked', async () => {
      const f = new Fake()
      const p = person()
      const forged = { ...pinFor(p), signature: b64(new Uint8Array(64)) }
      f.add(p, 'member', 0, forged)
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', blocked: [p.id] })
      expect(f.cryptoRecipients).toEqual([])
    })

    it('pins a first-sight member, then wraps to the pinned key', async () => {
      const f = new Fake()
      const p = f.add(person(), 'member', 0, null)
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'completed', rewrapped: 1 })
      expect(f.pinned).toEqual([p.id])
    })

    it('stops without wrapping when a first-sight pin cannot be stored', async () => {
      const f = new Fake()
      f.add(person(), 'member', 0, null)
      f.pinKeysError = new Error('offline')
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('incomplete')
      expect(f.cryptoRecipients).toEqual([])
    })

    it('stops without wrapping anything when the pin set cannot be read', async () => {
      const f = new Fake()
      f.add(person())
      f.listPinsError = new Error('offline')
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'incomplete', rewrapped: 0 })
      expect(f.cryptoRecipients).toEqual([])
      expect(f.rewrapBatches).toEqual([])
    })

    it("stops when a recipient's keys cannot be fetched", async () => {
      const f = new Fake()
      f.add(person())
      const deps = f.deps()
      const out = await runRotation(
        {
          ...deps,
          getUsers: async () => new Map(), // nothing readable
        },
        GROUP,
      )
      expect(out.status).toBe('incomplete')
      expect(f.cryptoRecipients).toEqual([])
    })

    it('says why the keys could not be fetched, so a 401 reads as a sign-in problem', async () => {
      const f = new Fake()
      const p = f.add(person())
      const out = await runRotation(
        {
          ...f.deps(),
          getUsers: async (_ids, onError) => {
            onError?.(new ApiError(401, 'not authenticated'))
            return new Map()
          },
        },
        GROUP,
      )
      expect(out.status).toBe('incomplete')
      expect(JSON.stringify(out)).toContain(`could not fetch keys for ${p.id}: not authenticated`)
    })
  })

  describe('admissions (#178)', () => {
    it('does not wrap to, or pin, a member nobody admitted, and does not complete', async () => {
      const f = new Fake()
      const real = f.add(person())
      // The server lists an account it made up: no admission record.
      const fake = f.add(person(), 'member', 0, null, null)

      const out = await runRotation(f.deps(), GROUP)

      expect(out).toEqual({
        status: 'blocked',
        blocked: [],
        unadmitted: [fake.id],
        rewrapped: 1,
      })
      expect(f.cryptoRecipients.flat()).toEqual([real.id])
      expect(f.pinned).toEqual([]) // an unadmitted account is not even pinned
      expect(f.gen(fake)).toBe(0)
      expect(f.completed).toEqual([])
    })

    it('refuses an admission the server forged (signed by a key that is not the inviter)', async () => {
      const f = new Fake()
      const fake = person()
      f.add(fake, 'member', 0, null, admissionOf(fake, { key: generateSigningKey() }))
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [fake.id] })
      expect(f.cryptoRecipients).toEqual([])
    })

    it('refuses a member whose served wrapping key is not the one admitted (key substitution)', async () => {
      const f = new Fake()
      const p = person()
      // Admitted with the real key; the server now serves another.
      f.add(p, 'member', 0, null, admissionOf(p))
      f.members.get(p.id)!.person = { ...p, wrapping: new Uint8Array(32).fill(200) }
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [p.id] })
      expect(f.cryptoRecipients).toEqual([])
      expect(f.pinned).toEqual([])
    })

    it("refuses another member's admission relabelled onto an account the server made up", async () => {
      const f = new Fake()
      const real = f.add(person())
      const fake = person()
      const stolen = { ...f.admissions.get(real.id)!, inviteeUserId: fake.id }
      f.add(fake, 'member', 0, null, stolen)
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [fake.id] })
      expect(f.cryptoRecipients.flat()).toEqual([real.id])
    })

    it('exempts the creator, who has no admission, and wraps to members a promoted admin invited', async () => {
      const f = new Fake()
      const { creator, myGrant } = f.promoted()
      const invited = person()
      f.add(invited, 'member', 0, 'auto', admissionOf(invited, { ref: myGrant.sortKey }))
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'completed', rewrapped: 2 })
      expect(new Set(f.cryptoRecipients.flat())).toEqual(new Set([creator.id, invited.id]))
    })

    it('does not exempt anyone else from a missing admission when the caller is not the creator', async () => {
      const f = new Fake()
      const { creator } = f.promoted()
      const fake = f.add(person(), 'member', 0, null, null)
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [fake.id] })
      expect(f.cryptoRecipients.flat()).toEqual([creator.id])
    })

    it('refuses an admission by someone who had lost the admin role by then', async () => {
      const f = new Fake()
      const { creatorKey, myGrant } = f.promoted()
      // The creator demoted the caller on 03-05; an admission dated 03-10 that
      // still cites the old grant cannot be the caller acting as an admin.
      const demoteRef = `GRANT#${ME}#2026-03-05#0000000000000004`
      f.grants.push({
        sortKey: demoteRef,
        subjectUserId: ME,
        grantedRole: 'member',
        grantorUserId: f.anchor.creatorUserId,
        grantorGrantRef: f.anchor.rootGrantSortKey,
        signature: b64(
          sign(
            creatorKey,
            SigningContext.RoleGrant,
            roleGrantPayload(GROUP, ME, 'member', demoteRef, f.anchor.rootGrantSortKey),
          ),
        ),
      })
      const late = person()
      f.add(late, 'member', 0, null, admissionOf(late, { ref: myGrant.sortKey, day: '2026-03-10' }))
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [late.id] })
      expect(f.cryptoRecipients.flat()).not.toContain(late.id)
    })

    it('wraps to a member admitted before the inviter was later demoted', async () => {
      const f = new Fake()
      const { creatorKey, myGrant } = f.promoted()
      const demoteRef = `GRANT#${ME}#2026-03-20#0000000000000005`
      f.grants.push({
        sortKey: demoteRef,
        subjectUserId: ME,
        grantedRole: 'member',
        grantorUserId: f.anchor.creatorUserId,
        grantorGrantRef: f.anchor.rootGrantSortKey,
        signature: b64(
          sign(
            creatorKey,
            SigningContext.RoleGrant,
            roleGrantPayload(GROUP, ME, 'member', demoteRef, f.anchor.rootGrantSortKey),
          ),
        ),
      })
      const early = person()
      f.add(
        early,
        'member',
        0,
        'auto',
        admissionOf(early, { ref: myGrant.sortKey, day: '2026-03-10' }),
      )
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('completed')
      expect(f.cryptoRecipients.flat()).toContain(early.id)
    })

    it.each([
      [
        'the records cannot be read',
        (f: Fake) => (f.listAdmissionsError = new Error('boom')),
        /boom/,
      ],
      [
        'the group anchor differs from the one pinned',
        (f: Fake) => {
          f.anchorPin = {
            creatorUserId: ME,
            creatorSigningPublicKey: b64(generateSigningKey().publicKey),
          }
        },
        /anchor changed/,
      ],
      [
        'the root grant is not served',
        (f: Fake) => {
          f.grants = []
        },
        /root grant/,
      ],
    ])('stops without wrapping to anyone when %s', async (_name, break_, reason) => {
      const f = new Fake()
      f.add(person())
      break_(f)
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('incomplete')
      expect(JSON.stringify(out)).toMatch(reason)
      expect(f.cryptoRecipients).toEqual([])
      expect(f.rewrapBatches).toEqual([])
      expect(f.completed).toEqual([])
    })

    it('reads the admissions only when a recipient needs checking', async () => {
      const f = new Fake()
      f.marker = undefined
      f.add(person(), 'member', 1) // already current: nobody is behind
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'none' })
      expect(f.admissionReads).toBe(0)
    })

    it('reads the admissions once per pass, not once per batch or member', async () => {
      const f = new Fake()
      for (let i = 0; i < 60; i++) f.add(person())
      await runRotation(f.deps(), GROUP)
      expect(f.admissionReads).toBe(1)
    })
  })

  describe('key reads', () => {
    it('reads each batch of recipients in one call, not one per member', async () => {
      const f = new Fake()
      const people = Array.from({ length: 30 }, () => f.add(person()))
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('completed')
      // 30 behind members at 25 per rewrap batch: two key reads, not thirty.
      // The single-id read between them is the grant chain's one look at the
      // creator's keys (#178), made once for the pass, not once per member.
      expect(f.userReads.map((ids) => ids.length)).toEqual([25, 1, 5])
      expect(f.userReads[1]).toEqual([ME])
      expect(new Set(f.userReads.flat())).toEqual(new Set([ME, ...people.map((p) => p.id)]))
    })
  })

  describe('exclude', () => {
    it('never wraps to an excluded user the server still lists, and does not complete', async () => {
      const f = new Fake()
      const ok = f.add(person())
      const removed = f.add(person()) // valid pin: only the exclude set stops this one
      const out = await runRotation(f.deps(), GROUP, { exclude: new Set([removed.id]) })
      expect(f.cryptoRecipients.flat()).toEqual([ok.id])
      expect(f.gen(removed)).toBe(0)
      expect(f.completed).toEqual([])
      expect(out.status).toBe('incomplete') // the server insists they are behind: fails safe
    })

    it('completes normally when the server honestly no longer lists them', async () => {
      const f = new Fake()
      f.add(person())
      const out = await runRotation(f.deps(), GROUP, { exclude: new Set(['gone-user']) })
      expect(out).toEqual({ status: 'completed', rewrapped: 1 })
    })

    it('keeps excluding across a restart', async () => {
      const f = new Fake()
      const removed = f.add(person())
      f.add(person())
      f.onRewrap[0] = () => {
        f.marker = startMarker(2)
        f.ownGeneration = 2
        f.members.get(ME)!.generation = 2
      }
      await runRotation(f.deps(), GROUP, { exclude: new Set([removed.id]) })
      expect(f.cryptoRecipients.flat()).not.toContain(removed.id)
    })
  })

  describe('signed start record (#178)', () => {
    // An admin other than the caller started the rotation; the caller resumes it.
    function resumedBy(f: Fake, removed: Person, o: Parameters<typeof startMarker>[1] = {}) {
      const starter = f.add(person(), 'admin', 1)
      f.marker = startMarker(1, {
        startedBy: starter.id,
        signer: starter.signing,
        removed: removed.id,
        ...o,
      })
      return starter
    }

    it('excludes the member the starter named, with no help from the caller', async () => {
      const f = new Fake()
      const ok = f.add(person())
      const removed = f.add(person()) // listed by the server, valid pin
      resumedBy(f, removed)
      const out = await runRotation(f.deps(), GROUP)
      expect(f.cryptoRecipients.flat()).toEqual([ok.id])
      expect(f.gen(removed)).toBe(0)
      expect(f.completed).toEqual([])
      expect(out.status).toBe('incomplete') // the server insists they are behind: fails safe
    })

    it('accepts a record the caller signed themselves', async () => {
      const f = new Fake()
      const removed = f.add(person())
      f.marker = startMarker(1, { removed: removed.id })
      await runRotation(f.deps(), GROUP)
      expect(f.cryptoRecipients).toEqual([])
      expect(f.gen(removed)).toBe(0)
    })

    it('stops, wrapping to no one, when the marker has no signed record', async () => {
      const f = new Fake()
      f.add(person())
      f.marker = startMarker(1, { unsigned: true })
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('incomplete')
      expect(JSON.stringify(out)).toContain('signed record')
      expect(f.cryptoRecipients).toEqual([])
      expect(f.completed).toEqual([])
    })

    it.each([
      ['another signer', (f: Fake, r: Person) => resumedBy(f, r, { signer: generateSigningKey() })],
      ['another subject', (f: Fake, r: Person) => resumedBy(f, r, { signedFor: { removed: 'x' } })],
      [
        'another generation',
        (f: Fake, r: Person) => resumedBy(f, r, { signedFor: { generation: 2 } }),
      ],
    ])('stops when the signature is by %s', async (_name, build) => {
      const f = new Fake()
      f.add(person())
      build(f, f.add(person()))
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('incomplete')
      expect(JSON.stringify(out)).toContain('does not verify')
      expect(f.cryptoRecipients).toEqual([])
    })

    it("stops when the starter's served keys disagree with the caller's pin", async () => {
      const f = new Fake()
      const removed = f.add(person())
      const starter = resumedBy(f, removed)
      // The server now serves different keys for the starter than the pin records.
      f.pins.set(starter.id, pinFor({ ...starter, signing: generateSigningKey() }))
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('incomplete')
      expect(JSON.stringify(out)).toContain('do not match your pin')
      expect(f.cryptoRecipients).toEqual([])
    })

    it("says why when the starter's keys cannot be fetched", async () => {
      const f = new Fake()
      const removed = f.add(person())
      const starter = resumedBy(f, removed)
      const deps = f.deps()
      const out = await runRotation(
        {
          ...deps,
          getUsers: async (ids, onError) => {
            if (ids.includes(starter.id)) {
              onError?.(new ApiError(401, 'not authenticated'))
              return new Map()
            }
            return deps.getUsers(ids, onError)
          },
        },
        GROUP,
      )
      expect(out.status).toBe('incomplete')
      expect(JSON.stringify(out)).toContain('not authenticated')
      expect(f.cryptoRecipients).toEqual([])
    })

    it('keeps excluding the named member after a restart on a newer marker', async () => {
      const f = new Fake()
      const removed = f.add(person())
      f.add(person())
      resumedBy(f, removed)
      f.onRewrap[0] = () => {
        // Another removal supersedes the marker mid-run, naming someone else.
        f.marker = startMarker(2)
        f.ownGeneration = 2
        f.members.get(ME)!.generation = 2
      }
      await runRotation(f.deps(), GROUP)
      expect(f.cryptoRecipients.flat()).not.toContain(removed.id)
    })
  })

  describe('describeRotation', () => {
    const label = (id: string) => `<${id}>`
    it('says nothing when there was nothing to do', () => {
      expect(describeRotation({ status: 'none' }, label)).toBeNull()
    })
    it('reports a finished rotation, with and without a count', () => {
      expect(describeRotation({ status: 'completed', rewrapped: 3 }, label)).toEqual({
        kind: 'info',
        text: 'Key rotation finished: 3 members moved to the new group key.',
      })
      expect(describeRotation({ status: 'completed', rewrapped: 0 }, label)?.text).toBe(
        'Key rotation finished.',
      )
    })
    it('reports a catch-up, singular and plural', () => {
      expect(describeRotation({ status: 'caught-up', rewrapped: 1 }, label)?.text).toMatch(
        /^1 member who had fallen behind was moved/,
      )
      expect(describeRotation({ status: 'caught-up', rewrapped: 2 }, label)?.text).toMatch(
        /^2 members who had fallen behind were moved/,
      )
    })
    it('names the people a pin check blocked, as an error', () => {
      const note = describeRotation({ status: 'blocked', blocked: ['x', 'y'], rewrapped: 1 }, label)
      expect(note?.kind).toBe('error')
      expect(note?.text).toContain('<x>, <y>')
      expect(note?.text).toContain('NOT given the new group key')
      expect(note?.text).not.toContain('invitation')
    })

    it('names members no invitation backs, and says so apart from a pin mismatch', () => {
      const only = describeRotation(
        { status: 'blocked', blocked: [], unadmitted: ['x'], rewrapped: 0 },
        label,
      )
      expect(only?.kind).toBe('error')
      expect(only?.text).toContain('<x> is listed as a member')
      expect(only?.text).toContain('invitation')
      expect(only?.text).not.toContain("don't match")
      expect(only?.text).toContain('NOT given the new group key')

      const both = describeRotation(
        { status: 'blocked', blocked: ['y'], unadmitted: ['a', 'b'], rewrapped: 0 },
        label,
      )
      expect(both?.text).toContain("<y> don't match")
      expect(both?.text).toContain('<a>, <b> are listed as members')
    })
    it('reports an incomplete run as an error with its reason, and cannot-resume as info', () => {
      const inc = describeRotation({ status: 'incomplete', reason: 'offline', rewrapped: 0 }, label)
      expect(inc).toMatchObject({ kind: 'error' })
      expect(inc?.text).toContain('offline')
      expect(describeRotation({ status: 'cannot-resume', reason: 'r' }, label)?.kind).toBe('info')
    })
  })

  describe('who may run it', () => {
    it('does nothing for a non-admin', async () => {
      const f = new Fake()
      f.add(person())
      f.role = 'member'
      expect(await runRotation(f.deps(), GROUP)).toEqual({ status: 'none' })
      expect(f.rewrapBatches).toEqual([])
    })

    it('does nothing for a public group', async () => {
      const f = new Fake()
      f.add(person())
      f.visibility = 'public'
      expect(await runRotation(f.deps(), GROUP)).toEqual({ status: 'none' })
    })

    it('says cannot-resume, and writes nothing, when the caller is behind the rotation', async () => {
      const f = new Fake()
      f.add(person())
      f.ownGeneration = 0
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('cannot-resume')
      expect(f.rewrapBatches).toEqual([])
      expect(f.completed).toEqual([])
    })
  })

  describe('catch-up with no rotation running', () => {
    it("brings a behind member up to the caller's generation without completing anything", async () => {
      const f = new Fake()
      f.marker = undefined
      const late = f.add(person())
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'caught-up', rewrapped: 1 })
      expect(f.gen(late)).toBe(1)
      expect(f.completed).toEqual([])
    })

    it('does nothing when nobody is behind', async () => {
      const f = new Fake()
      f.marker = undefined
      f.add(person(), 'member', 1)
      expect(await runRotation(f.deps(), GROUP)).toEqual({ status: 'none' })
      expect(f.rewrapBatches).toEqual([])
    })
  })
})
