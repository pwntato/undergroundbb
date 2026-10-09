// Tests for the rotation job. The server is an in-memory fake that applies the
// same rules the real one does (all-or-nothing batch, generation checks), so a
// test of "resume after a lost response" exercises the job's own logic against
// realistic state changes rather than canned replies. Pins are signed with real
// keys, so a pin rejection is evaluatePin's decision, not a malformed fixture.

import { describe, expect, it } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type {
  GroupDetail,
  KeychainLink,
  MemberEntry,
  MemberRole,
  RewrapEntry,
  TakeOverRotationRequest,
} from '@/lib/api/groups'
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

/**
 * The chain link for `generation` as the server serves one after a signed
 * removal (#178): `signer` (default: the caller) names `removed` for
 * generation + 1. Overrides model a link that was blanked or forged.
 */
function removalLink(
  generation: number,
  o: {
    remover?: string
    signer?: SigningKey
    removed?: string
    signedFor?: { removed?: string; generation?: number }
    unsigned?: boolean
  } = {},
): KeychainLink {
  const remover = o.remover ?? ME
  const removed = o.removed ?? REMOVED
  const base = { generation, wrapped: { nonce: 'n', ciphertext: 'c' } }
  if (o.unsigned) return base
  const payload = rotationStartPayload(
    GROUP,
    remover,
    o.signedFor?.removed ?? removed,
    o.signedFor?.generation ?? generation + 1,
  )
  return {
    ...base,
    removerUserId: remover,
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
    /** Signed group-key generation (default 0). */
    generation?: number
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
  const payload = admissionPayload(
    GROUP,
    inviter,
    p.id,
    ed,
    x,
    inviteId,
    ref,
    day,
    o.generation ?? 0,
  )
  return {
    inviteeUserId: p.id,
    inviterUserId: inviter,
    inviteId,
    inviteeEd25519PublicKey: b64(ed),
    inviteeX25519PublicKey: b64(x),
    inviterGrantRef: ref,
    day,
    generation: o.generation ?? 0,
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
  /**
   * The chain links the server serves (#178). Unset means an honest history:
   * one link per generation below ownGeneration, each the caller removing
   * REMOVED. A test sets it to model who was removed, or what a server hides.
   */
  links: KeychainLink[] | undefined
  keychainPageSize = 1000
  keychainError: Error | undefined
  keychainReads: [number, number][] = []
  anchorPin: StoredAnchorPin | null = null
  listAdmissionsError: Error | undefined
  admissionReads = 0

  // A member who LEFT started this rotation (#178) and minted no key. They are
  // no longer listed but are still a user the server can serve.
  outsiders = new Map<string, Person>()
  takeOverError: Error | undefined
  /** Keys the server claims a person superseded, with no proof (it just serves them). */
  fabricatedSuperseded = new Map<string, SigningKey>()
  /** Errors the next takeover calls throw, in order, before succeeding. */
  takeOverFailures: Error[] = []
  /** How many times the job asked the worker to mint a takeover key. */
  mints = 0
  /** Models a server that accepts a takeover but leaves the leaver's marker as it was. */
  ignoreTakeOver = false
  takeOvers: { request: TakeOverRotationRequest; subject: string }[] = []
  /** Runs once, before the first takeover reaches the server (a racing admin). */
  beforeTakeOver: (() => void) | undefined

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
            if (r) return [[id, served(r.person)] as const]
            const o = this.outsiders.get(id)
            if (!o) return []
            const extra = this.fabricatedSuperseded.get(id)
            const projection = served(o)
            return [
              [
                id,
                extra
                  ? {
                      ...projection,
                      supersededSigningKeys: [
                        {
                          publicKey: b64(extra.publicKey),
                          from: '2026-01-01',
                          until: '2026-02-01',
                        },
                      ],
                    }
                  : projection,
              ] as const,
            ]
          }),
        )
      },
      getKeychain: async (_g, from, to) => {
        this.keychainReads.push([from, to])
        if (this.keychainError) throw this.keychainError
        const all =
          this.links ?? Array.from({ length: this.ownGeneration }, (_, n) => removalLink(n))
        const inRange = all.filter((l) => l.generation >= from && l.generation <= to)
        const page = inRange.slice(0, this.keychainPageSize)
        const next = inRange[this.keychainPageSize]
        return { links: page, ...(next !== undefined && { nextFrom: next.generation }) }
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
      takeOverCrypto: async (req) => {
        this.mints++
        const generation = req.ownGeneration + 1
        return {
          generation,
          link: { nonce: 'new-link-n', ciphertext: 'new-link-c' },
          removerWrappedKey: { ephemeralPub: 'ne', nonce: 'nn', ciphertext: 'nc' },
          startSignature: b64(
            sign(
              me,
              SigningContext.RotationStart,
              rotationStartPayload(GROUP, ME, req.subjectUserId, generation),
            ),
          ),
        }
      },
      takeOverRotation: async (_g, request) => {
        const hook = this.beforeTakeOver
        this.beforeTakeOver = undefined
        hook?.()
        const queued = this.takeOverFailures.shift()
        if (queued) throw queued
        if (this.takeOverError) throw this.takeOverError
        if (this.ignoreTakeOver) return
        const m = this.marker
        // The server only takes over a leaver's unclaimed marker for the next generation.
        if (!m || m.startedBy !== m.removedUserId || m.generation !== request.generation) {
          throw new ApiError(409, 'not active', 'rotation_not_active')
        }
        const subject = m.removedUserId!
        this.takeOvers.push({ request, subject })
        // It replaces the leaver's marker with the admin's and writes the link.
        this.marker = {
          generation: request.generation,
          startedAt: 't',
          startedBy: ME,
          removedUserId: subject,
          startSignature: request.startSignature,
        }
        this.links = [
          ...(this.links ?? []).filter((l) => l.generation < request.generation - 1),
          {
            generation: request.generation - 1,
            wrapped: request.link,
            removerUserId: ME,
            removedUserId: subject,
            startSignature: request.startSignature,
          },
        ]
        this.ownGeneration = request.generation
        this.members.get(ME)!.generation = request.generation
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

  describe('removal history (#178)', () => {
    // The signed removal at generation 1 (link 0) names `x`, who is still
    // listed by the server and still holds the admission they had before.
    function relisted(f: Fake, admissionGeneration: number): Person {
      const x = person()
      f.add(x, 'member', 0, 'auto', admissionOf(x, { generation: admissionGeneration }))
      f.links = [removalLink(0, { removed: x.id })]
      return x
    }

    it('refuses a removed member the server re-lists with their old admission', async () => {
      const f = new Fake()
      const real = f.add(person())
      const x = relisted(f, 0)

      const out = await runRotation(f.deps(), GROUP)

      expect(out).toEqual({ status: 'blocked', blocked: [], unadmitted: [x.id], rewrapped: 1 })
      expect(f.cryptoRecipients.flat()).toEqual([real.id])
      expect(f.pinned).toEqual([])
      expect(f.completed).toEqual([])
    })

    it('wraps to a removed member who was invited again after the removal', async () => {
      const f = new Fake()
      const x = relisted(f, 1)

      const out = await runRotation(f.deps(), GROUP)

      expect(out).toEqual({ status: 'completed', rewrapped: 1 })
      expect(f.cryptoRecipients.flat()).toEqual([x.id])
    })

    it('judges a repeat removal against the newest one', async () => {
      const f = new Fake()
      f.ownGeneration = 2
      f.marker = startMarker(2)
      f.members.get(ME)!.generation = 2
      const x = person()
      // Removed at generation 1, invited again at generation 1, removed again at 2.
      f.add(x, 'member', 0, 'auto', admissionOf(x, { generation: 1 }))
      f.links = [removalLink(0, { removed: x.id }), removalLink(1, { removed: x.id })]
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [x.id] })
    })

    it('refuses the creator re-listed after another admin removed them, until invited again', async () => {
      const f = new Fake()
      const { creator } = f.promoted()
      f.links = [removalLink(0, { removed: creator.id })]
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [creator.id] })
      expect(f.cryptoRecipients.flat()).not.toContain(creator.id)
    })

    it('still exempts a creator nobody removed', async () => {
      const f = new Fake()
      const { creator } = f.promoted()
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'completed', rewrapped: 1 })
      expect(f.cryptoRecipients.flat()).toEqual([creator.id])
    })

    it('accepts a record signed by another admin whose served keys match the pin', async () => {
      const f = new Fake()
      const eve = f.add(person(), 'admin')
      const x = person()
      f.add(x, 'member', 0, 'auto', admissionOf(x, { generation: 0 }))
      f.links = [removalLink(0, { remover: eve.id, signer: eve.signing, removed: x.id })]
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'blocked', unadmitted: [x.id] })
      expect(f.cryptoRecipients.flat()).toEqual([eve.id])
    })

    it('stops when the other admin who signed a removal serves keys that do not match the pin', async () => {
      const f = new Fake()
      const eve = f.add(person(), 'admin')
      f.pins.set(eve.id, pinFor({ ...eve, signing: generateSigningKey() }))
      f.links = [removalLink(0, { remover: eve.id, signer: eve.signing })]
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('incomplete')
      expect(JSON.stringify(out)).toContain('do not match your pin')
      expect(f.cryptoRecipients).toEqual([])
    })

    const stops: [string, (f: Fake) => void, string][] = [
      ['a generation is missing from the chain', (f) => (f.links = []), 'missing the removal'],
      [
        'a link is blanked',
        (f) => (f.links = [removalLink(0, { unsigned: true })]),
        'without a signed record',
      ],
      [
        'a link is signed by another key',
        (f) => (f.links = [removalLink(0, { signer: generateSigningKey() })]),
        'does not verify',
      ],
      [
        'a link names someone else than the signature covers',
        (f) => (f.links = [removalLink(0, { signedFor: { removed: 'someone-else' } })]),
        'does not verify',
      ],
      [
        'a link is replayed at another generation',
        (f) => (f.links = [removalLink(0, { signedFor: { generation: 2 } })]),
        'does not verify',
      ],
      [
        'a link lists a generation twice',
        (f) => (f.links = [removalLink(0), removalLink(0)]),
        'twice',
      ],
      [
        'the chain cannot be read',
        (f) => (f.keychainError = new Error('boom')),
        "could not read the group's removal history: boom",
      ],
    ]
    for (const [name, arrange, reason] of stops) {
      it(`wraps to no one when ${name}`, async () => {
        const f = new Fake()
        f.add(person())
        arrange(f)
        const out = await runRotation(f.deps(), GROUP)
        expect(out.status).toBe('incomplete')
        expect(JSON.stringify(out)).toContain(reason)
        expect(f.cryptoRecipients).toEqual([])
        expect(f.completed).toEqual([])
      })
    }

    it('reads every page of the chain', async () => {
      const f = new Fake()
      f.ownGeneration = 3
      f.marker = startMarker(3)
      f.members.get(ME)!.generation = 3
      f.keychainPageSize = 1
      f.add(person())
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'completed', rewrapped: 1 })
      expect(f.keychainReads.map(([from]) => from)).toEqual([0, 1, 2])
    })

    it('does not read the chain when nobody needs checking', async () => {
      const f = new Fake()
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'completed', rewrapped: 0 })
      expect(f.keychainReads).toEqual([])
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

  describe('a rotation a member started by leaving (#178)', () => {
    // ME holds generation 1; a member who has since LEFT started the rotation
    // to 2 and signed only that they are the member removed. No key exists yet.
    function leftBehind(f: Fake, trust: 'admission' | 'pin' | 'none' = 'admission') {
      const leaver = person()
      f.outsiders.set(leaver.id, leaver)
      // What makes the leaver's key worth signing a removal for: the inviter's
      // admission (kept by the leave for exactly this), or the caller's pin.
      if (trust === 'admission') f.admissions.set(leaver.id, admissionOf(leaver))
      if (trust === 'pin') f.pins.set(leaver.id, pinFor(leaver))
      f.ownGeneration = 1
      f.members.get(ME)!.generation = 1
      f.marker = startMarker(2, {
        startedBy: leaver.id,
        signer: leaver.signing,
        removed: leaver.id,
      })
      f.links = [removalLink(0)]
      return leaver
    }

    // PR #209 round 3: the takeover is the first path where the client turns a
    // marker into ITS OWN new signature, so a leaver's key the server merely
    // served (first sight) is not enough.
    describe("trusting the leaver's key before signing their removal", () => {
      it('takes nothing over for a forged leave: an unpinned member, a key the server made up', async () => {
        const f = new Fake()
        const leaver = leftBehind(f, 'none')
        const forged = { ...leaver, signing: generateSigningKey() }
        f.outsiders.set(leaver.id, forged)
        f.marker = startMarker(2, {
          startedBy: leaver.id,
          signer: forged.signing,
          removed: leaver.id,
        })
        const out = await runRotation(f.deps(), GROUP)
        expect(out).toMatchObject({
          status: 'incomplete',
          reason: expect.stringMatching(/pin|admi/),
        })
        expect(f.mints).toBe(0)
        expect(f.takeOvers).toEqual([])
      })

      it('takes nothing over for a genuine-looking leave by someone nobody admitted or pinned', async () => {
        const f = new Fake()
        leftBehind(f, 'none')
        const out = await runRotation(f.deps(), GROUP)
        expect(out.status).toBe('incomplete')
        expect(f.mints).toBe(0)
        expect(f.takeOvers).toEqual([])
      })

      it('takes nothing over when the admission is for other keys than the ones served now', async () => {
        const f = new Fake()
        const leaver = leftBehind(f, 'none')
        const forged = { ...leaver, signing: generateSigningKey() }
        f.outsiders.set(leaver.id, forged)
        f.admissions.set(leaver.id, admissionOf(leaver)) // admits the REAL key
        f.marker = startMarker(2, {
          startedBy: leaver.id,
          signer: forged.signing,
          removed: leaver.id,
        })
        expect((await runRotation(f.deps(), GROUP)).status).toBe('incomplete')
        expect(f.mints).toBe(0)
      })

      it("takes nothing over when a fabricated 'superseded' key signed it and the real key keeps the admission valid", async () => {
        const f = new Fake()
        const leaver = leftBehind(f, 'admission') // admits the leaver's REAL key
        const fabricated = generateSigningKey()
        f.fabricatedSuperseded.set(leaver.id, fabricated)
        f.marker = startMarker(2, {
          startedBy: leaver.id,
          signer: fabricated,
          removed: leaver.id,
        })
        const out = await runRotation(f.deps(), GROUP)
        expect(out).toMatchObject({
          status: 'incomplete',
          reason: expect.stringMatching(/key their admission names/),
        })
        expect(f.mints).toBe(0)
      })

      it("takes nothing over when a fabricated 'superseded' key signed it for the creator", async () => {
        const f = new Fake()
        const { creator } = f.promoted()
        const fabricated = generateSigningKey()
        f.members.delete(creator.id)
        f.pins.delete(creator.id)
        f.outsiders.set(creator.id, creator)
        f.fabricatedSuperseded.set(creator.id, fabricated)
        f.marker = startMarker(2, {
          startedBy: creator.id,
          signer: fabricated,
          removed: creator.id,
        })
        f.links = [removalLink(0)]
        const out = await runRotation(f.deps(), GROUP)
        expect(out).toMatchObject({
          status: 'incomplete',
          reason: expect.stringMatching(/anchor names/),
        })
        expect(f.mints).toBe(0)
      })

      it('takes nothing over for a creator the removal history already lists as removed', async () => {
        const f = new Fake()
        const { creator, creatorKey } = f.promoted()
        f.members.delete(creator.id)
        f.pins.delete(creator.id)
        f.outsiders.set(creator.id, creator)
        f.marker = startMarker(2, {
          startedBy: creator.id,
          signer: creatorKey,
          removed: creator.id,
        })
        f.links = [removalLink(0, { removed: creator.id })] // removed earlier, at generation 1
        expect((await runRotation(f.deps(), GROUP)).status).toBe('incomplete')
        expect(f.mints).toBe(0)
      })

      // PR #209 round 4: a member removed once and re-invited AFTER the removal
      // is admitted again (isAdmitted), so their leave must be takeable.
      it('takes over the leave of a member who was removed once and re-invited after the removal', async () => {
        const f = new Fake()
        const leaver = leftBehind(f, 'none')
        f.links = [removalLink(0, { removed: leaver.id })] // removed, removedAt = 1
        f.admissions.set(leaver.id, admissionOf(leaver, { generation: 1 }))
        const out = await runRotation(f.deps(), GROUP)
        expect(out.status).toBe('completed')
        expect(f.takeOvers).toHaveLength(1)
      })

      it('takes over the leave of a creator who was removed once and re-invited after the removal', async () => {
        const f = new Fake()
        const { creator, creatorKey, myGrant } = f.promoted()
        f.members.delete(creator.id)
        f.pins.delete(creator.id)
        f.outsiders.set(creator.id, creator)
        f.admissions.set(creator.id, admissionOf(creator, { generation: 1, ref: myGrant.sortKey }))
        f.marker = startMarker(2, {
          startedBy: creator.id,
          signer: creatorKey,
          removed: creator.id,
        })
        f.links = [removalLink(0, { removed: creator.id })]
        const out = await runRotation(f.deps(), GROUP)
        expect(out.status).toBe('completed')
        expect(f.takeOvers).toHaveLength(1)
      })

      it('takes nothing over when the server fabricates the key AND an admission for it, not signed by the inviter', async () => {
        const f = new Fake()
        const leaver = leftBehind(f, 'none')
        const forged = { ...leaver, signing: generateSigningKey() }
        f.outsiders.set(leaver.id, forged)
        // The record names the forged key, signed by a key that is nobody's
        // inviter: only the admission's own verification can refuse it.
        f.admissions.set(leaver.id, admissionOf(forged, { key: generateSigningKey() }))
        f.marker = startMarker(2, {
          startedBy: leaver.id,
          signer: forged.signing,
          removed: leaver.id,
        })
        const out = await runRotation(f.deps(), GROUP)
        expect(out).toMatchObject({
          status: 'incomplete',
          reason: expect.stringMatching(/no admission signed/),
        })
        expect(f.mints).toBe(0)
      })

      it('takes over on a pin alone, with no admission to check', async () => {
        const f = new Fake()
        leftBehind(f, 'pin')
        const out = await runRotation(f.deps(), GROUP)
        expect(out.status).toBe('completed')
        expect(f.takeOvers).toHaveLength(1)
        expect(f.admissionReads).toBe(0) // the pin settled it
      })

      it('takes nothing over when the admissions or the removal history cannot be read', async () => {
        const f = new Fake()
        leftBehind(f, 'admission')
        f.listAdmissionsError = new Error('boom')
        expect((await runRotation(f.deps(), GROUP)).status).toBe('incomplete')
        expect(f.mints).toBe(0)
      })

      it("accepts the group creator's own key as the anchor says, and no other", async () => {
        const ok = new Fake()
        const { creator, creatorKey } = ok.promoted()
        for (const f of [ok]) {
          f.members.delete(creator.id)
          f.pins.delete(creator.id)
          f.outsiders.set(creator.id, creator)
          f.marker = startMarker(2, {
            startedBy: creator.id,
            signer: creatorKey,
            removed: creator.id,
          })
          f.links = [removalLink(0)]
        }
        expect((await runRotation(ok.deps(), GROUP)).status).toBe('completed')
        expect(ok.takeOvers).toHaveLength(1)

        const forged = new Fake()
        const c2 = forged.promoted()
        const fakeKey = generateSigningKey()
        forged.members.delete(c2.creator.id)
        forged.pins.delete(c2.creator.id)
        forged.outsiders.set(c2.creator.id, { ...c2.creator, signing: fakeKey })
        forged.marker = startMarker(2, {
          startedBy: c2.creator.id,
          signer: fakeKey,
          removed: c2.creator.id,
        })
        forged.links = [removalLink(0)]
        expect((await runRotation(forged.deps(), GROUP)).status).toBe('incomplete')
        expect(forged.mints).toBe(0)
      })
    })

    it('tries the takeover once more after a lost race that left the marker unclaimed', async () => {
      const f = new Fake()
      leftBehind(f)
      f.takeOverFailures = [new ApiError(409, 'busy', 'conflict_retry')]
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('completed')
      expect(f.takeOvers).toHaveLength(1)
    })

    it('says to run again, not that another admin must resume, when the retry is busy too', async () => {
      const f = new Fake()
      leftBehind(f)
      f.takeOverFailures = [
        new ApiError(409, 'busy', 'conflict_retry'),
        new ApiError(409, 'busy', 'conflict_retry'),
      ]
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toMatchObject({ status: 'incomplete', reason: expect.stringMatching(/again/) })
      expect(f.takeOvers).toEqual([])
    })

    it('mints the key itself, naming the leaver, then re-wraps everyone and finishes', async () => {
      const f = new Fake()
      const leaver = leftBehind(f)
      const bob = f.add(person(), 'member', 1)
      const out = await runRotation(f.deps(), GROUP)
      expect(out).toEqual({ status: 'completed', rewrapped: 1 })
      expect(f.takeOvers).toHaveLength(1)
      const { request, subject } = f.takeOvers[0]!
      expect(subject).toBe(leaver.id)
      expect(request.generation).toBe(2)
      // Signed by the admin, naming the same leaver as removed.
      expect(request.startSignature).toBe(
        b64(sign(me, SigningContext.RotationStart, rotationStartPayload(GROUP, ME, leaver.id, 2))),
      )
      expect(f.gen(bob)).toBe(2)
      expect(f.completed).toEqual([2])
    })

    it('never wraps to the leaver, who is no longer listed but could be re-listed', async () => {
      const f = new Fake()
      const leaver = leftBehind(f)
      // A server re-lists the leaver with their old admission.
      f.members.set(leaver.id, { person: leaver, role: 'member', generation: 0 })
      f.admissions.set(leaver.id, admissionOf(leaver))
      const out = await runRotation(f.deps(), GROUP)
      expect(f.cryptoRecipients.flat()).not.toContain(leaver.id)
      expect(out.status).toBe('incomplete') // the rotation cannot finish while they are "behind"
    })

    it('does not trust a marker whose start record does not verify', async () => {
      const f = new Fake()
      const leaver = leftBehind(f)
      // Signed by someone other than the leaver it names as starter.
      f.marker = startMarker(2, {
        startedBy: leaver.id,
        signer: generateSigningKey(),
        removed: leaver.id,
      })
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('incomplete')
      expect(f.mints).toBe(0)
      expect(f.takeOvers).toEqual([])
    })

    it("does not take over an admin's rotation", async () => {
      const f = new Fake()
      leftBehind(f)
      // An admin's removal (startedBy is not the removed member).
      f.marker = startMarker(2, { startedBy: ME, removed: REMOVED })
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('cannot-resume')
      expect(f.mints).toBe(0)
      expect(f.takeOvers).toEqual([])
    })

    it('stands back when another admin took it over first', async () => {
      const f = new Fake()
      const leaver = leftBehind(f)
      f.beforeTakeOver = () => {
        // The other admin wins the race: the marker is theirs now, at generation 2.
        f.marker = startMarker(2, { startedBy: 'other-admin', removed: leaver.id })
      }
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('cannot-resume')
      expect(f.takeOvers).toEqual([])
    })

    it('stops on any other takeover failure', async () => {
      const f = new Fake()
      leftBehind(f)
      f.takeOverError = new ApiError(500, 'boom', 'internal')
      expect((await runRotation(f.deps(), GROUP)).status).toBe('incomplete')
      expect(f.takeOvers).toEqual([])
    })

    it('does not take over when this admin is not at the leaver’s generation', async () => {
      const f = new Fake()
      leftBehind(f)
      f.ownGeneration = 0
      f.members.get(ME)!.generation = 0
      expect((await runRotation(f.deps(), GROUP)).status).toBe('cannot-resume')
      expect(f.mints).toBe(0)
      expect(f.takeOvers).toEqual([])
    })

    it('tries once, not forever, if the marker is still the leaver’s after a takeover', async () => {
      const f = new Fake()
      leftBehind(f)
      f.ignoreTakeOver = true
      const out = await runRotation(f.deps(), GROUP)
      expect(out.status).toBe('cannot-resume')
      expect(f.mints).toBe(1)
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
      expect(only?.text).toContain('backs them')
      expect(only?.text).toContain('remove them and invite them again')
      expect(only?.text).toContain('invitation')
      expect(only?.text).not.toContain("don't match")
      expect(only?.text).toContain('NOT given the new group key')

      const both = describeRotation(
        { status: 'blocked', blocked: ['y'], unadmitted: ['a', 'b'], rewrapped: 0 },
        label,
      )
      expect(both?.text).toContain("<y> don't match")
      expect(both?.text).toContain('<a>, <b> are listed as members')
      expect(both?.text).toContain('backs them')
      expect(both?.text).not.toContain('backs it')
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
