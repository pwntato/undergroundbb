// Dormancy is derived on the client from the roster's wrapEpoch and each
// member's served keyEpoch (#62). These pin the comparison and every way a
// member is NOT reported, since a false "dormant" is a prompt to approve keys.

import { describe, expect, it, vi } from 'vitest'
import type { MemberEntry } from '@/lib/api/groups'
import type { UserProjection } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { generateSigningKey } from '@/lib/crypto/ed25519'
import { findDormant, loadDormancy } from './dormancy'

const ME = 'a0000000-0000-4000-8000-000000000001'
const BOB = 'b0000000-0000-4000-8000-000000000002'
const CAROL = 'c0000000-0000-4000-8000-000000000003'
const DAVE = 'd0000000-0000-4000-8000-000000000004'

function user(id: string, keyEpoch: number, over: Partial<UserProjection> = {}): UserProjection {
  return {
    userId: id,
    username: id.slice(0, 1),
    signingPublicKey: bytesToBase64(generateSigningKey().publicKey),
    wrappingPublicKey: bytesToBase64(new Uint8Array(32).fill(5)),
    supersededSigningKeys: [],
    keyEpoch,
    ...over,
  }
}

function member(userId: string, wrapEpoch: number | undefined, generation = 0): MemberEntry {
  return {
    userId,
    role: 'member',
    generation,
    ...(wrapEpoch !== undefined && { wrapEpoch }),
  }
}

const usersOf = (...us: UserProjection[]) => new Map(us.map((u) => [u.userId, u]))

describe('findDormant', () => {
  it('reports a member whose entry is wrapped before their latest rotation', () => {
    const out = findDormant([member(BOB, 0)], usersOf(user(BOB, 1)), ME, 0, 'rotating')
    expect(out.map((d) => [d.userId, d.keyEpoch, d.wrapEpoch])).toEqual([[BOB, 1, 0]])
    expect(out[0]?.fingerprint).toMatch(/\S/)
  })

  it('does not report a member whose entry matches or is past their epoch', () => {
    const members = [member(BOB, 1), member(CAROL, 2)]
    expect(findDormant(members, usersOf(user(BOB, 1), user(CAROL, 1)), ME, 0, 'rotating')).toEqual(
      [],
    )
  })

  it('does not report a member who never rotated', () => {
    expect(findDormant([member(BOB, 0)], usersOf(user(BOB, 0)), ME, 0, 'rotating')).toEqual([])
  })

  it('leaves out the caller, a deleted account, a missing projection and an unknown wrapEpoch', () => {
    const members = [member(ME, 0), member(BOB, 0), member(CAROL, 0), member(DAVE, undefined)]
    const users = usersOf(user(ME, 1), user(BOB, 1, { deleted: true }), user(DAVE, 1))
    expect(findDormant(members, users, ME, 0, 'rotating')).toEqual([])
  })

  it('says whether the entry is behind the caller’s generation or at it', () => {
    const members = [member(BOB, 0, 1), member(CAROL, 0, 2)]
    const out = findDormant(members, usersOf(user(BOB, 1), user(CAROL, 1)), ME, 2, 'rotating')
    expect(out.map((d) => [d.userId, d.entry])).toEqual([
      [BOB, 'behind'],
      [CAROL, 'current'],
    ])
  })

  it('calls every dormant member in an Open group a plain wrap, whatever their generation', () => {
    const members = [member(BOB, 0, 1), member(CAROL, 0, 2)]
    const out = findDormant(members, usersOf(user(BOB, 1), user(CAROL, 1)), ME, 2, 'open')
    expect(out.map((d) => [d.userId, d.entry])).toEqual([
      [BOB, 'open'],
      [CAROL, 'open'],
    ])
  })

  it('keeps roster order', () => {
    const members = [member(CAROL, 0), member(BOB, 0)]
    const out = findDormant(members, usersOf(user(BOB, 1), user(CAROL, 1)), ME, 0, 'rotating')
    expect(out.map((d) => d.userId)).toEqual([CAROL, BOB])
  })

  it('has no fingerprint when the served keys are malformed', () => {
    const bad = user(BOB, 1, { signingPublicKey: '!!' })
    expect(
      findDormant([member(BOB, 0)], usersOf(bad), ME, 0, 'rotating')[0]?.fingerprint,
    ).toBeNull()
  })
})

describe('loadDormancy', () => {
  it('reads everyone but the caller and reports the dormant ones', async () => {
    const getUsers = vi.fn().mockResolvedValue(usersOf(user(BOB, 1), user(CAROL, 0)))
    const out = await loadDormancy(
      { getUsers, selfUserId: ME },
      [member(ME, 0), member(BOB, 0), member(CAROL, 0)],
      0,
      'rotating',
    )
    expect(getUsers.mock.calls[0]?.[0]).toEqual([BOB, CAROL])
    expect(out.state === 'ready' && out.dormant.map((d) => d.userId)).toEqual([BOB])
  })

  it('is unavailable, not clean, when a read failed', async () => {
    const getUsers = vi.fn(async (_ids: readonly string[], onError?: (e: unknown) => void) => {
      onError?.(new Error('503'))
      return usersOf(user(CAROL, 1))
    })
    const out = await loadDormancy(
      { getUsers, selfUserId: ME },
      [member(BOB, 0), member(CAROL, 0)],
      0,
      'rotating',
    )
    expect(out).toEqual({ state: 'unavailable' })
  })

  it('asks for nobody when the caller is the whole roster', async () => {
    const getUsers = vi.fn()
    const out = await loadDormancy({ getUsers, selfUserId: ME }, [member(ME, 0)], 0, 'rotating')
    expect(out).toEqual({ state: 'ready', dormant: [] })
    expect(getUsers).not.toHaveBeenCalled()
  })
})
