import { describe, expect, it } from 'vitest'
import { filterMembersByQuery } from './memberSearch'

const members = [{ userId: 'a' }, { userId: 'b' }, { userId: 'c' }, { userId: 'd' }]
const usernames = new Map([
  ['a', 'Alice'],
  ['b', 'alan'],
  ['c', 'bob'],
  ['d', ''],
])

describe('filterMembersByQuery', () => {
  it('returns everyone for an empty or blank query', () => {
    expect(filterMembersByQuery(members, usernames, '')).toEqual(members)
    expect(filterMembersByQuery(members, usernames, '   ')).toEqual(members)
  })
  it('matches a case-insensitive prefix, keeping order', () => {
    expect(filterMembersByQuery(members, usernames, 'AL').map((m) => m.userId)).toEqual(['a', 'b'])
    expect(filterMembersByQuery(members, usernames, ' bo ').map((m) => m.userId)).toEqual(['c'])
  })
  it('does not match in the middle of a name', () => {
    expect(filterMembersByQuery(members, usernames, 'ice')).toEqual([])
  })
  it('matches what the row shows for a deleted or unresolved member', () => {
    const withUnresolved = [...members, { userId: 'e1234567-0000-4000-8000-000000000000' }]
    expect(filterMembersByQuery(withUnresolved, usernames, 'deleted').map((m) => m.userId)).toEqual(
      ['d'],
    )
    expect(filterMembersByQuery(withUnresolved, usernames, 'E1234').map((m) => m.userId)).toEqual([
      'e1234567-0000-4000-8000-000000000000',
    ])
  })
  it('keeps members with something open on their row, whatever they match', () => {
    expect(
      filterMembersByQuery(members, usernames, 'bo', new Set(['a'])).map((m) => m.userId),
    ).toEqual(['a', 'c'])
    expect(filterMembersByQuery(members, usernames, '', new Set(['a']))).toEqual(members)
  })
})
