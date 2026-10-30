import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from './ed25519'
import { makeKeyChange } from './own-history.testkit'
import { atOnSignedDay, checkCommentSignature } from './comment-check'
import { signedPayload } from './payload'

const GROUP = 'a0000000-0000-4000-8000-000000000001'
const AUTHOR = 'b0000000-0000-4000-8000-000000000002'
const DAY = '2026-10-20'
const PATH = '0001.0002'
const b64 = bytesToBase64
const CIPHERTEXT = new Uint8Array(60).fill(7)

const k0 = generateSigningKey()
const k1 = generateSigningKey()

function signed(
  key: SigningKey,
  over: Partial<{ context: SigningContext; path: string; day: string; generation: number }> = {},
) {
  const payload = signedPayload(
    AUTHOR,
    GROUP,
    `CMT#${over.path ?? PATH}`,
    over.generation ?? 0,
    over.day ?? DAY,
    CIPHERTEXT,
  )
  return b64(sign(key, over.context ?? SigningContext.Comment, payload))
}

const unrotated = { signingPublicKey: b64(k0.publicKey), keyChanges: [] }
const rotatedOn = (day: string) => ({
  signingPublicKey: b64(k1.publicKey),
  keyChanges: [makeKeyChange({ userId: AUTHOR, from: k0, to: k1, epoch: 1, day }).change],
})

const check = (
  signature: string,
  author: Parameters<typeof checkCommentSignature>[0]['author'] | null = unrotated,
  over: Partial<{ path: string; signedDay: string; generation: number; authorUserId: string }> = {},
) =>
  checkCommentSignature({
    groupId: GROUP,
    authorUserId: over.authorUserId ?? AUTHOR,
    path: over.path ?? PATH,
    generation: over.generation ?? 0,
    signedDay: over.signedDay ?? DAY,
    ciphertext: b64(CIPHERTEXT),
    signature,
    author: author ?? undefined,
  })

describe('checkCommentSignature', () => {
  it('accepts a comment signed by the author under the comment context', () => {
    expect(check(signed(k0))).toEqual({ kind: 'valid' })
  })

  it('rejects a signature made under the post context', () => {
    expect(check(signed(k0, { context: SigningContext.Post }))).toEqual({ kind: 'invalid' })
  })

  it('rejects a comment moved to another path, day, generation or author', () => {
    const sig = signed(k0)
    expect(check(sig, unrotated, { path: '0001.0003' })).toEqual({ kind: 'invalid' })
    expect(check(sig, unrotated, { signedDay: '2026-10-21' })).toEqual({ kind: 'invalid' })
    expect(check(sig, unrotated, { generation: 1 })).toEqual({ kind: 'invalid' })
    expect(check(sig, unrotated, { authorUserId: GROUP })).toEqual({ kind: 'invalid' })
  })

  it('rejects a signature by someone else', () => {
    expect(check(signed(generateSigningKey()))).toEqual({ kind: 'invalid' })
  })

  it('uses the signed day to pick the key interval across a rotation', () => {
    const author = rotatedOn('2026-10-25')
    expect(check(signed(k0), author)).toEqual({ kind: 'valid' }) // before the rotation
    expect(check(signed(k1, { day: '2026-10-26' }), author, { signedDay: '2026-10-26' })).toEqual({
      kind: 'valid',
    })
    // The new key cannot vouch for a day before it existed.
    expect(check(signed(k1), author)).toEqual({ kind: 'invalid' })
  })

  it('is unchecked, never invalid, when the author keys were not read', () => {
    expect(check(signed(k0), null).kind).toBe('unchecked')
  })

  it('treats a malformed signed day as invalid and a malformed signature as unchecked', () => {
    expect(check(signed(k0), unrotated, { signedDay: 'yesterday' })).toEqual({ kind: 'invalid' })
    expect(check('not base64 !!', unrotated).kind).toBe('unchecked')
  })
})

describe('atOnSignedDay', () => {
  it('compares the decrypted time to the signed day', () => {
    expect(atOnSignedDay(DAY, '2026-10-20T23:59:59.999Z')).toBe(true)
    expect(atOnSignedDay(DAY, '2026-10-21T00:00:00.000Z')).toBe(false)
    expect(atOnSignedDay('garbage', 'garbage-time')).toBe(false)
  })
})
