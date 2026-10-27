import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64'
import { SigningContext, generateSigningKey, sign, type SigningKey } from './ed25519'
import { wrapRecordPayload } from './group'
import { makeKeyChange } from './own-history.testkit'
import { checkWrapRecord, type WireWrapRecord } from './wrap-record'

const GROUP = 'a0000000-0000-4000-8000-000000000001'
const ADMIN = 'b0000000-0000-4000-8000-000000000002'
const MEMBER = 'c0000000-0000-4000-8000-000000000003'
const DAY = '2026-10-20'
const b64 = bytesToBase64

const k0 = generateSigningKey()
const k1 = generateSigningKey()

function recordBy(
  key: SigningKey,
  over: Partial<{
    wrapper: string
    member: string
    generation: number
    epoch: number
    reason: 'self' | 'approval'
    day: string
    group: string
  }> = {},
): WireWrapRecord {
  const wrapper = over.wrapper ?? ADMIN
  const reason = over.reason ?? 'approval'
  const day = over.day ?? DAY
  const payload = wrapRecordPayload(
    over.group ?? GROUP,
    wrapper,
    over.member ?? MEMBER,
    over.generation ?? 3,
    over.epoch ?? 2,
    reason,
    day,
  )
  return {
    wrapperUserId: wrapper,
    reason,
    day,
    signature: b64(sign(key, SigningContext.WrapRecord, payload)),
  }
}

const unrotated = { signingPublicKey: b64(k0.publicKey), keyChanges: [] }
const rotatedOn = (day: string) => ({
  signingPublicKey: b64(k1.publicKey),
  keyChanges: [makeKeyChange({ userId: ADMIN, from: k0, to: k1, epoch: 1, day }).change],
})

function check(
  record: WireWrapRecord | undefined,
  wrapper: Parameters<typeof checkWrapRecord>[0]['wrapper'] | null = unrotated,
  over: { memberUserId?: string; generation?: number; wrapEpoch?: number | undefined } = {},
) {
  return checkWrapRecord({
    groupId: GROUP,
    memberUserId: over.memberUserId ?? MEMBER,
    generation: over.generation ?? 3,
    wrapEpoch: 'wrapEpoch' in over ? over.wrapEpoch : 2,
    record,
    wrapper: wrapper ?? undefined,
  })
}

describe('checkWrapRecord', () => {
  it('is approved when the wrapper signed this entry', () => {
    expect(check(recordBy(k0))).toEqual({ kind: 'approved', wrapperUserId: ADMIN })
  })

  it('is self when the member signed their own entry', () => {
    const rec = recordBy(k0, { wrapper: MEMBER, reason: 'self' })
    expect(check(rec, unrotated)).toEqual({ kind: 'self' })
  })

  it('is none when the entry carries no record, without needing the wrapper', () => {
    expect(check(undefined, null)).toEqual({ kind: 'none' })
  })

  it('is invalid when signed for another generation than the entry serves', () => {
    expect(check(recordBy(k0, { generation: 2 }))).toEqual({ kind: 'invalid' })
  })

  it('is invalid when signed to another KeyEpoch than the entry serves', () => {
    expect(check(recordBy(k0, { epoch: 1 }))).toEqual({ kind: 'invalid' })
  })

  it('is invalid when signed for another member or another group', () => {
    expect(check(recordBy(k0, { member: ADMIN }))).toEqual({ kind: 'invalid' })
    expect(check(recordBy(k0, { group: MEMBER }))).toEqual({ kind: 'invalid' })
  })

  it('is invalid when signed by a key that is not the wrapper’s', () => {
    expect(check(recordBy(generateSigningKey()))).toEqual({ kind: 'invalid' })
  })

  it('is invalid when reason self comes from someone other than the member', () => {
    expect(check(recordBy(k0, { reason: 'self' }))).toEqual({ kind: 'invalid' })
  })

  it('is invalid when reason approval comes from the member themselves', () => {
    const rec = recordBy(k0, { wrapper: MEMBER, reason: 'approval' })
    expect(check(rec, unrotated)).toEqual({ kind: 'invalid' })
  })

  it('is invalid for a reason it does not know', () => {
    const rec = { ...recordBy(k0), reason: 'admin' }
    expect(check(rec)).toEqual({ kind: 'invalid' })
  })

  it('is invalid for a malformed day', () => {
    expect(check({ ...recordBy(k0), day: '20261020' })).toEqual({ kind: 'invalid' })
  })

  it('accepts a record signed by a key the wrapper has since rotated away from', () => {
    expect(check(recordBy(k0, { day: '2026-10-10' }), rotatedOn('2026-10-15'))).toEqual({
      kind: 'approved',
      wrapperUserId: ADMIN,
    })
  })

  it('accepts the old key on the rotation day itself', () => {
    expect(check(recordBy(k0, { day: '2026-10-15' }), rotatedOn('2026-10-15')).kind).toBe(
      'approved',
    )
  })

  it('refuses the old key for a day after it was rotated away', () => {
    expect(check(recordBy(k0, { day: '2026-10-16' }), rotatedOn('2026-10-15'))).toEqual({
      kind: 'invalid',
    })
  })

  it('accepts the current key for a day after it was introduced', () => {
    expect(check(recordBy(k1, { day: '2026-10-16' }), rotatedOn('2026-10-15')).kind).toBe(
      'approved',
    )
  })

  it('accepts the new key on the rotation day itself', () => {
    expect(check(recordBy(k1, { day: '2026-10-15' }), rotatedOn('2026-10-15')).kind).toBe(
      'approved',
    )
  })

  it('refuses the current key for a day before it existed', () => {
    expect(check(recordBy(k1, { day: '2026-10-14' }), rotatedOn('2026-10-15'))).toEqual({
      kind: 'invalid',
    })
  })

  it('is unchecked, never none, when the wrapper’s keys were not read', () => {
    expect(check(recordBy(k0), null).kind).toBe('unchecked')
  })

  it('is unchecked when the server did not serve the entry’s KeyEpoch', () => {
    expect(check(recordBy(k0), unrotated, { wrapEpoch: undefined }).kind).toBe('unchecked')
  })

  it('is unchecked when the wrapper’s chain does not end at the key served', () => {
    const served = { signingPublicKey: b64(k0.publicKey), keyChanges: rotatedOn(DAY).keyChanges }
    expect(check(recordBy(k0), served).kind).toBe('unchecked')
  })

  it('is unchecked when the wrapper’s served key is malformed', () => {
    expect(check(recordBy(k0), { signingPublicKey: '!!', keyChanges: [] }).kind).toBe('unchecked')
  })
})
