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
  postTimeSuspect,
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

/** A post signed over `day` rather than the sort key's day, as an edit is (#45). */
function editedBy(key: SigningKey, day: string) {
  const signed = signedPayload(AUTHOR, GROUP, SORT_KEY, 0, day, CIPHERTEXT)
  return {
    sortKey: SORT_KEY,
    generation: 0,
    ciphertext: b64(CIPHERTEXT),
    signature: b64(sign(key, SigningContext.Post, signed)),
  }
}

describe('checkPostSignature on an edited post (signedDay, #45)', () => {
  const EDIT_DAY = '2026-10-25'

  it('checks the signature over the served signedDay in place of the sort key day', () => {
    const post = editedBy(k0, EDIT_DAY)
    expect(
      checkPostSignature({
        groupId: GROUP,
        authorUserId: AUTHOR,
        ...post,
        signedDay: EDIT_DAY,
        author: unrotated,
      }),
    ).toEqual({ kind: 'valid' })
    // Without it the reader would check the sort key's day, which the edit did not sign.
    expect(check(post)).toEqual({ kind: 'invalid' })
  })

  it('is invalid when the served signedDay is not the day that was signed', () => {
    const post = postBy(k0)
    expect(
      checkPostSignature({
        groupId: GROUP,
        authorUserId: AUTHOR,
        ...post,
        signedDay: EDIT_DAY,
        author: unrotated,
      }),
    ).toEqual({ kind: 'invalid' })
    expect(
      checkPostSignature({
        groupId: GROUP,
        authorUserId: AUTHOR,
        ...post,
        signedDay: DAY,
        author: unrotated,
      }),
    ).toEqual({ kind: 'valid' })
  })

  it('picks the key interval from the edit day: an edit after a rotation is under the new key', () => {
    const author = rotatedOn('2026-10-22')
    const post = editedBy(k1, EDIT_DAY)
    expect(
      checkPostSignature({
        groupId: GROUP,
        authorUserId: AUTHOR,
        ...post,
        signedDay: EDIT_DAY,
        author,
      }),
    ).toEqual({ kind: 'valid' })
    // The old key signing on the edit day is refused: it was retired before then.
    const stale = editedBy(k0, EDIT_DAY)
    expect(
      checkPostSignature({
        groupId: GROUP,
        authorUserId: AUTHOR,
        ...stale,
        signedDay: EDIT_DAY,
        author,
      }),
    ).toEqual({ kind: 'invalid' })
  })

  it('is invalid when signedDay is earlier than the day the post was filed, even from the key of that day', () => {
    // k0 was retired on 10-22; the post is filed on 10-30 but "signed" on 10-20 by k0.
    const author = rotatedOn('2026-10-22')
    const sortKey = 'POST#2026-10-30#00112233445566ff'
    const signedDay = '2026-10-20'
    const signed = signedPayload(AUTHOR, GROUP, sortKey, 0, signedDay, CIPHERTEXT)
    const post = {
      sortKey,
      generation: 0,
      ciphertext: b64(CIPHERTEXT),
      signature: b64(sign(k0, SigningContext.Post, signed)),
    }
    expect(
      checkPostSignature({ groupId: GROUP, authorUserId: AUTHOR, ...post, signedDay, author }),
    ).toEqual({ kind: 'invalid' })
    // An edit on the filing day itself is still fine.
    const same = signedPayload(AUTHOR, GROUP, sortKey, 0, '2026-10-30', CIPHERTEXT)
    expect(
      checkPostSignature({
        groupId: GROUP,
        authorUserId: AUTHOR,
        sortKey,
        generation: 0,
        ciphertext: b64(CIPHERTEXT),
        signature: b64(sign(k1, SigningContext.Post, same)),
        signedDay: '2026-10-30',
        author,
      }),
    ).toEqual({ kind: 'valid' })
  })

  it('is invalid for a malformed signedDay, even one the author signed over', () => {
    for (const signedDay of ['', 'yesterday', '2026-10-25T00:00:00Z']) {
      const post = editedBy(k0, signedDay)
      expect(
        checkPostSignature({
          groupId: GROUP,
          authorUserId: AUTHOR,
          ...post,
          signedDay,
          author: unrotated,
        }),
        signedDay,
      ).toEqual({ kind: 'invalid' })
    }
  })

  it('is invalid for a malformed signedDay', () => {
    const post = editedBy(k0, EDIT_DAY)
    for (const signedDay of ['', '2026-10-25T00:00:00Z', 'yesterday']) {
      expect(
        checkPostSignature({
          groupId: GROUP,
          authorUserId: AUTHOR,
          ...post,
          signedDay,
          author: unrotated,
        }),
        signedDay,
      ).toEqual({ kind: 'invalid' })
    }
  })
})

describe('postTimeSuspect', () => {
  const AT = `${DAY}T10:00:00.000Z`
  const base = { sortKey: SORT_KEY, signedDay: undefined, at: AT, editedAt: undefined }

  it('a never-edited post is suspect only when at is off the sort key day', () => {
    expect(postTimeSuspect(base)).toBe(false)
    expect(postTimeSuspect({ ...base, at: '2026-10-21T10:00:00.000Z' })).toBe(true)
    // A re-signed version 1 post carries a signedDay too; its at is still the sort key's day.
    expect(postTimeSuspect({ ...base, signedDay: '2026-10-21' })).toBe(false)
  })

  it('an edited post needs editedAt on the signed day and not before at', () => {
    const edited = { ...base, signedDay: '2026-10-25', editedAt: '2026-10-25T08:00:00.000Z' }
    expect(postTimeSuspect(edited)).toBe(false)
    expect(postTimeSuspect({ ...edited, editedAt: '2026-10-24T23:59:59.999Z' })).toBe(true)
    expect(postTimeSuspect({ ...edited, at: '2026-10-21T10:00:00.000Z' })).toBe(true)
    // Edited the same day: no signedDay needed, editedAt must not precede at.
    expect(postTimeSuspect({ ...base, editedAt: `${DAY}T10:00:00.000Z` })).toBe(false)
    expect(postTimeSuspect({ ...base, editedAt: `${DAY}T09:59:59.999Z` })).toBe(true)
    expect(postTimeSuspect({ ...base, editedAt: '2026-10-25T08:00:00.000Z' })).toBe(true)
  })
})
