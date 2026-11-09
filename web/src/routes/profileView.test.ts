import { describe, expect, it } from 'vitest'
import type { UserProjection } from '@/lib/api/users'
import { bioFits, bioLength, formatMemberSince, profileView } from './profileView'

const user = (over: Partial<UserProjection> = {}): UserProjection => ({
  userId: 'u1',
  username: 'alice',
  signingPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  wrappingPublicKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
  supersededSigningKeys: [],
  keyEpoch: 0,
  ...over,
})

describe('formatMemberSince', () => {
  it('writes the day out', () => {
    expect(formatMemberSince('2026-11-08')).toBe('8 November 2026')
    expect(formatMemberSince('2026-01-31')).toBe('31 January 2026')
  })
  it('is null for a missing or impossible day', () => {
    expect(formatMemberSince(undefined)).toBeNull()
    expect(formatMemberSince('')).toBeNull()
    expect(formatMemberSince('2026-13-01')).toBeNull()
    expect(formatMemberSince('2026-02-30')).toBeNull()
    expect(formatMemberSince('2026-04-31')).toBeNull()
    expect(formatMemberSince('2026-05-00')).toBeNull()
    expect(formatMemberSince('not a day')).toBeNull()
  })
})

describe('profileView', () => {
  it('carries the username, bio and member-since, and computes a fingerprint locally', () => {
    const v = profileView(user({ bio: 'hi', createdDay: '2026-11-08' }))
    expect(v).toMatchObject({ username: 'alice', bio: 'hi', memberSince: '8 November 2026' })
    expect(v.deleted).toBe(false)
    expect(v.fingerprint).toMatch(/^(\d{5}-){11}\d{5}$/)
  })
  it('shows nothing of a deleted account', () => {
    const v = profileView(
      user({ username: 'ghost', deleted: true, bio: 'leftover', createdDay: '2026-11-08' }),
    )
    expect(v).toMatchObject({
      deleted: true,
      username: '',
      bio: '',
      memberSince: null,
      fingerprint: null,
    })
  })
  it('has no fingerprint when the served keys are malformed', () => {
    expect(profileView(user({ signingPublicKey: '%%%' })).fingerprint).toBeNull()
  })
})

describe('bio length', () => {
  it('counts characters, not bytes or UTF-16 units, after trimming', () => {
    expect(bioLength('  héllo 😀 ')).toBe(7)
  })
  it('fits at the cap and not above it', () => {
    expect(bioFits('a'.repeat(280))).toBe(true)
    expect(bioFits('a'.repeat(281))).toBe(false)
    expect(bioFits('😀'.repeat(280))).toBe(true)
    expect(bioFits('')).toBe(true)
  })
})
