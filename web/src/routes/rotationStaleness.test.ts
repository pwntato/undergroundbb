import { describe, expect, it } from 'vitest'
import { describeAge, ROTATION_STALE_AFTER_MS, rotationNotice } from './rotationStaleness'
import type { MembersView } from './runGroupMembers'

const NOW = Date.parse('2026-10-03T12:00:00Z')
const startedAgo = (ms: number): string => new Date(NOW - ms).toISOString()

function view(overrides: Partial<MembersView> = {}): MembersView {
  return {
    groupId: 'g1',
    members: [],
    myRole: 'admin',
    myGrantSortKey: 'GRANT#x',
    revocationMode: 'rotating',
    myGeneration: 2,
    rotation: { generation: 2, startedAt: startedAgo(ROTATION_STALE_AFTER_MS), startedBy: 'u1' },
    ...overrides,
  }
}

describe('rotationNotice', () => {
  it('says nothing when no rotation is running', () => {
    const { rotation: _unused, ...noMarker } = view()
    expect(rotationNotice(noMarker, NOW)).toBeNull()
  })

  it('says nothing before the deadline', () => {
    const v = view({
      rotation: {
        generation: 2,
        startedAt: startedAgo(ROTATION_STALE_AFTER_MS - 1),
        startedBy: 'u1',
      },
    })
    expect(rotationNotice(v, NOW)).toBeNull()
  })

  it('warns at the deadline, to an admin who holds the new key, as resumable', () => {
    expect(rotationNotice(view(), NOW)).toMatchObject({ kind: 'resumable', startedBy: 'u1' })
  })

  it('tells an admin who is behind the marker that another admin must finish it', () => {
    expect(rotationNotice(view({ myGeneration: 1 }), NOW)).toMatchObject({
      kind: 'needs-other-admin',
    })
  })

  it('does not call an admin whose key is ahead of the marker resumable', () => {
    expect(rotationNotice(view({ myGeneration: 3 }), NOW)).toMatchObject({
      kind: 'needs-other-admin',
    })
  })

  it('tells only admins', () => {
    expect(rotationNotice(view({ myRole: 'member' }), NOW)).toBeNull()
    expect(rotationNotice(view({ myRole: 'ambassador' }), NOW)).toBeNull()
  })

  it('treats an unparseable timestamp as stale rather than hiding the rotation', () => {
    const v = view({ rotation: { generation: 2, startedAt: 'garbage', startedBy: 'u1' } })
    expect(rotationNotice(v, NOW)).toMatchObject({ kind: 'resumable', ageMs: null })
  })
})

describe('describeAge', () => {
  it.each([
    [null, 'a while'],
    [60 * 60_000, 'about 1 hour'],
    [3 * 60 * 60_000, 'about 3 hours'],
    [49 * 60 * 60_000, 'about 2 days'],
    [59 * 60_000, '59 minutes'],
  ])('%s -> %s', (ms, text) => {
    expect(describeAge(ms)).toBe(text)
  })
})
