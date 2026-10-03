import { describe, expect, it } from 'vitest'
import {
  catchUpResult,
  describeAge,
  ROTATION_STALE_AFTER_MS,
  rotationNotice,
} from './rotationStaleness'
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
    expect(rotationNotice(noMarker, NOW, 'incomplete')).toBeNull()
  })

  it('says nothing before the deadline', () => {
    const v = view({
      rotation: {
        generation: 2,
        startedAt: startedAgo(ROTATION_STALE_AFTER_MS - 1),
        startedBy: 'u1',
      },
    })
    expect(rotationNotice(v, NOW, 'incomplete')).toBeNull()
  })

  it('says nothing until the catch-up has ended, so it never speaks over a running job', () => {
    expect(rotationNotice(view(), NOW, null)).toBeNull()
  })

  it.each(['completed', 'caught-up', 'none'] as const)('says nothing after a %s catch-up', (s) => {
    expect(rotationNotice(view(), NOW, s)).toBeNull()
  })

  it.each([
    ['cannot-resume', 'needs-other-admin'],
    ['incomplete', 'stopped'],
    ['blocked', 'blocked'],
  ] as const)('at the deadline, a %s catch-up is a %s notice', (outcome, kind) => {
    expect(rotationNotice(view(), NOW, outcome)).toMatchObject({ kind, startedBy: 'u1' })
  })

  it('does not send an admin whose key is ahead of the marker to another admin', () => {
    expect(rotationNotice(view({ myGeneration: 3 }), NOW, 'cannot-resume')).toMatchObject({
      kind: 'ahead',
    })
  })

  it('tells only admins', () => {
    expect(rotationNotice(view({ myRole: 'member' }), NOW, 'incomplete')).toBeNull()
    expect(rotationNotice(view({ myRole: 'ambassador' }), NOW, 'incomplete')).toBeNull()
  })

  it('treats an unparseable timestamp as stale rather than hiding the rotation', () => {
    const v = view({ rotation: { generation: 2, startedAt: 'garbage', startedBy: 'u1' } })
    expect(rotationNotice(v, NOW, 'incomplete')).toMatchObject({ kind: 'stopped', ageMs: null })
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

describe('catchUpResult', () => {
  const label = (id: string): string => id
  const stale = view({ myGeneration: 1 })

  it('records the status and reloads only after a completed rotation', () => {
    expect(catchUpResult({ status: 'completed', rewrapped: 2 }, view(), NOW, label)).toMatchObject({
      status: 'completed',
      reload: true,
      error: null,
    })
    expect(
      catchUpResult({ status: 'incomplete', reason: 'x', rewrapped: 0 }, view(), NOW, label).reload,
    ).toBe(false)
  })

  it('routes an error outcome to error and leaves message empty', () => {
    const fx = catchUpResult(
      { status: 'incomplete', reason: 'offline', rewrapped: 0 },
      view(),
      NOW,
      label,
    )
    expect(fx.error).toContain('offline')
    expect(fx.message).toBeNull()
  })

  it('drops the cannot-resume info line when the stale banner says the same thing', () => {
    const outcome = { status: 'cannot-resume', reason: 'r' } as const
    expect(catchUpResult(outcome, stale, NOW, label).message).toBeNull()
  })

  it('keeps the cannot-resume info line before the deadline, when no banner will show', () => {
    const outcome = { status: 'cannot-resume', reason: 'r' } as const
    const fresh = view({
      myGeneration: 1,
      rotation: { generation: 2, startedAt: startedAgo(1000), startedBy: 'u1' },
    })
    expect(catchUpResult(outcome, fresh, NOW, label).message).toContain('has to be finished')
  })

  it('keeps the info line when there is no view to show a banner from', () => {
    const outcome = { status: 'cannot-resume', reason: 'r' } as const
    expect(catchUpResult(outcome, null, 0, label).message).not.toBeNull()
  })
})
