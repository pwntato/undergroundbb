import { describe, expect, it } from 'vitest'
import type { LoadState } from './GroupList'
import type { GroupListEntry } from '@/lib/api/groups'
import { failedFrom, loadingFrom, refetchKey, stillPending } from './useGroupsLoad'

const ready: LoadState = { status: 'ready', groups: [] }

describe('refetch keeps the list on screen', () => {
  it('a fetch starting over a ready list leaves it, over anything else shows loading', () => {
    expect(loadingFrom(ready)).toBe(ready)
    expect(loadingFrom({ status: 'error' })).toEqual({ status: 'loading' })
    expect(loadingFrom({ status: 'loading' })).toEqual({ status: 'loading' })
  })
  it('a failed fetch over a ready list leaves it, otherwise it is the error', () => {
    expect(failedFrom(ready)).toBe(ready)
    expect(failedFrom({ status: 'loading' })).toEqual({ status: 'error' })
  })
})

describe('refetchKey', () => {
  it('is the same across pages of one group, so moving inside a group does not refetch', () => {
    const k = refetchKey('/groups/g1/posts')
    expect(refetchKey('/groups/g1/posts/p9')).toBe(k)
    expect(refetchKey('/groups/g1/members')).toBe(k)
    expect(refetchKey('/groups/g1/settings')).toBe(k)
    expect(refetchKey('/groups/g1/invite')).toBe(k)
  })
  it('differs between groups and for every other page', () => {
    expect(refetchKey('/groups/g1/posts')).not.toBe(refetchKey('/groups/g2/posts'))
    expect(refetchKey('/groups/g1/posts')).not.toBe(refetchKey('/'))
    expect(refetchKey('/directory')).toBe('/directory')
    expect(refetchKey('/groups/new')).toBe('/groups/new')
  })
  it('refetches when a join ends in membership: /join is not folded into the group', () => {
    expect(refetchKey('/groups/g1/join')).not.toBe(refetchKey('/groups/g1/posts'))
  })
})

describe('stillPending', () => {
  const made = { groupId: 'g1' } as GroupListEntry
  it('keeps the new group until a fetched list includes it, then drops it', () => {
    expect(stillPending(made, [{ groupId: 'other' }])).toBe(made)
    expect(stillPending(made, [])).toBe(made)
    expect(stillPending(made, [{ groupId: 'g1' }])).toBeNull()
    expect(stillPending(null, [{ groupId: 'g1' }])).toBeNull()
  })
})
