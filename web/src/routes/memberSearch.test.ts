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
  it('never matches a deleted or unresolved member once a query is typed', () => {
    expect(filterMembersByQuery([...members, { userId: 'e' }], usernames, 'e')).toEqual([])
    expect(filterMembersByQuery(members, usernames, 'd')).toEqual([])
  })
})
