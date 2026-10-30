import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from './ed25519'
import { makeKeyChange } from './own-history.testkit'
import { signedPayload } from './payload'
import {
  atOnSortKeyDay,
  checkPostSignature,
  groupOfPostId,
  postIdOf,
  sortKeyDay,
} from './post-check'

const GROUP = 'a0000000-0000-4000-8000-000000000001'
const AUTHOR = 'b0000000-0000-4000-8000-000000000002'
const DAY = '2026-10-20'
const SORT_KEY = `POST#${DAY}#00112233445566ff`
const b64 = bytesToBase64

const k0 = generateSigningKey()
const k1 = generateSigningKey()
const CIPHERTEXT = new Uint8Array(60).fill(7)

function postBy(
  key: SigningKey,
  over: Partial<{
    author: string
    group: string
    sortKey: string
    signedKey: string
    generation: number
    signedGeneration: number
    ciphertext: Uint8Array
  }> = {},
) {
  const sortKey = over.sortKey ?? SORT_KEY
  const ciphertext = over.ciphertext ?? CIPHERTEXT
  const signed = signedPayload(
    over.author ?? AUTHOR,
    over.group ?? GROUP,
    over.signedKey ?? sortKey,
    over.signedGeneration ?? over.generation ?? 0,
    (over.signedKey ?? sortKey).slice(5, 15),
    CIPHERTEXT,
  )
  return {
    sortKey,
    generation: over.generation ?? 0,
    ciphertext: b64(ciphertext),
    signature: b64(sign(key, SigningContext.Post, signed)),
  }
}

const unrotated = { signingPublicKey: b64(k0.publicKey), keyChanges: [] }
const rotatedOn = (day: string) => ({
  signingPublicKey: b64(k1.publicKey),
  keyChanges: [makeKeyChange({ userId: AUTHOR, from: k0, to: k1, epoch: 1, day }).change],
})

function check(
  post: ReturnType<typeof postBy>,
  author: Parameters<typeof checkPostSignature>[0]['author'] | null = unrotated,
  over: { authorUserId?: string; groupId?: string } = {},
) {
  return checkPostSignature({
    groupId: over.groupId ?? GROUP,
    authorUserId: over.authorUserId ?? AUTHOR,
    ...post,
    author: author ?? undefined,
  })
}

describe('checkPostSignature', () => {
  it('is valid when the author signed this address and ciphertext', () => {
    expect(check(postBy(k0))).toEqual({ kind: 'valid' })
  })

  it('is invalid when each signed field is not the one served', () => {
    expect(check(postBy(k0, { signedKey: `POST#${DAY}#0000000000000000` }))).toEqual({
      kind: 'invalid',
    })
    expect(check(postBy(k0, { signedGeneration: 1 }))).toEqual({ kind: 'invalid' })
    expect(check(postBy(k0, { ciphertext: new Uint8Array(60).fill(8) }))).toEqual({
      kind: 'invalid',
    })
    expect(check(postBy(k0), unrotated, { groupId: AUTHOR })).toEqual({ kind: 'invalid' })
    expect(check(postBy(k0), unrotated, { authorUserId: GROUP })).toEqual({ kind: 'invalid' })
  })

  it('is invalid when signed by a key that is not the author’s', () => {
    expect(check(postBy(generateSigningKey()))).toEqual({ kind: 'invalid' })
  })

  it('is unchecked, never invalid, when the author’s keys were not read', () => {
    expect(check(postBy(k0), null).kind).toBe('unchecked')
  })

  it('is unchecked when the served material is malformed or the history does not verify', () => {
    expect(check(postBy(k0), { signingPublicKey: '***', keyChanges: [] }).kind).toBe('unchecked')
    const forged = rotatedOn('2026-10-10')
    const broken = {
      ...forged,
      keyChanges: [{ ...forged.keyChanges[0]!, newSignature: b64(new Uint8Array(64)) }],
    }
    expect(check(postBy(k1), broken).kind).toBe('unchecked')
  })

  it('accepts the key that was current on the post’s day, either side of a rotation', () => {
    const rotated = rotatedOn('2026-10-25')
    expect(check(postBy(k0), rotated)).toEqual({ kind: 'valid' })
    const after = postBy(k1, { sortKey: 'POST#2026-10-26#00112233445566ff' })
    expect(check(after, rotated)).toEqual({ kind: 'valid' })
  })

  it('refuses a superseded key on a day after it was retired, and the new key before it began', () => {
    const rotated = rotatedOn('2026-10-25')
    const lateOld = postBy(k0, { sortKey: 'POST#2026-10-26#00112233445566ff' })
    expect(check(lateOld, rotated)).toEqual({ kind: 'invalid' })
    expect(check(postBy(k1), rotated)).toEqual({ kind: 'invalid' })
  })

  it('accepts both keys on the rotation day itself', () => {
    const rotated = rotatedOn(DAY)
    expect(check(postBy(k0), rotated)).toEqual({ kind: 'valid' })
    expect(check(postBy(k1), rotated)).toEqual({ kind: 'valid' })
  })

  it('is invalid for a malformed sort key', () => {
    expect(check(postBy(k0, { sortKey: 'POST#2026-10-20#xyz', signedKey: SORT_KEY })).kind).toBe(
      'invalid',
    )
  })
})

describe('the sort key’s day', () => {
  it('reads the day and nothing else', () => {
    expect(sortKeyDay(SORT_KEY)).toBe(DAY)
    expect(sortKeyDay('POST#2026-10-20')).toBeUndefined()
    expect(sortKeyDay('DESIGNATION#x')).toBeUndefined()
  })

  it('accepts a time on that UTC day and refuses the next and the previous', () => {
    expect(atOnSortKeyDay(SORT_KEY, '2026-10-20T00:00:00.000Z')).toBe(true)
    expect(atOnSortKeyDay(SORT_KEY, '2026-10-20T23:59:59.999Z')).toBe(true)
    expect(atOnSortKeyDay(SORT_KEY, '2026-10-21T00:00:00.000Z')).toBe(false)
    expect(atOnSortKeyDay(SORT_KEY, '2026-10-19T23:59:59.999Z')).toBe(false)
    expect(atOnSortKeyDay('garbage', '2026-10-20T00:00:00.000Z')).toBe(false)
  })
})

describe('postIdOf', () => {
  it('joins the group and the sort key without its POST# prefix', () => {
    expect(postIdOf(GROUP, SORT_KEY)).toBe(`${GROUP}#${DAY}#00112233445566ff`)
  })

  it('refuses a sort key that is not a post', () => {
    for (const bad of [
      '',
      'CMT#0001',
      `POST#${DAY}`,
      `POST#${DAY}#00112233445566F`,
      `x${SORT_KEY}`,
    ]) {
      expect(postIdOf(GROUP, bad), bad).toBeUndefined()
    }
  })
})

describe('groupOfPostId', () => {
  it('reads the group out of a post id, the reverse of postIdOf', () => {
    expect(groupOfPostId(postIdOf(GROUP, SORT_KEY)!)).toBe(GROUP)
  })

  it('refuses anything that is not a post id', () => {
    for (const bad of [
      '',
      GROUP,
      `${GROUP}#${DAY}`,
      `${GROUP}#${DAY}#00112233445566F`,
      `${GROUP}#${DAY}#00112233445566ff#extra`,
      `x${GROUP}#${DAY}#00112233445566ff`,
      `short#${DAY}#00112233445566ff`,
    ]) {
      expect(groupOfPostId(bad), bad).toBeUndefined()
    }
  })
})
