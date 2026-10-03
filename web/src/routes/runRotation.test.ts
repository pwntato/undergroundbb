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
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import { runRotation, type RotationDeps } from './runRotation'

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

interface Row {
  person: Person
  role: MemberRole
  generation: number
}

class Fake {
  members = new Map<string, Row>()
  marker: { generation: number } | undefined = { generation: 1 }
  ownGeneration = 1
  role: GroupDetail['role'] = 'admin'
  visibility: GroupDetail['visibility'] = 'private'
  pins = new Map<string, PinRecord>()
  pinKeysError: Error | undefined
  listPinsError: Error | undefined

  // call logs
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
  ): Person {
    this.members.set(p.id, { person: p, role, generation })
    if (pin === 'auto') this.pins.set(p.id, pinFor(p))
    else if (pin !== null) this.pins.set(p.id, pin)
    return p
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
          ...(this.marker
            ? { rotation: { generation: this.marker.generation, startedAt: 't', startedBy: ME } }
            : {}),
        }) as GroupDetail,
      listAllMembers: async () =>
        [...this.members.values()].map((r): MemberEntry => ({
          userId: r.person.id,
          role: r.role,
          generation: r.generation,
        })),
      getUser: async (id) => {
        const r = this.members.get(id)
        if (!r) throw new ApiError(404, 'no such user')
        return served(r.person)
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
    f.marker = { generation: 1 }
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
      f.marker = { generation: 2 } // a newer rotation began meanwhile
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
      f.marker = { generation: 2 } // superseded after the first batch of 25 landed
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
          getUser: async () => {
            throw new Error('offline')
          },
        },
        GROUP,
      )
      expect(out.status).toBe('incomplete')
      expect(f.cryptoRecipients).toEqual([])
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
