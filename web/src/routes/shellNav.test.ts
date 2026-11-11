import { describe, expect, it } from 'vitest'
import { ACCOUNT_LINKS, PLACE_LINKS, isCurrentGroup, isCurrentPath } from './shellNav'

describe('isCurrentPath', () => {
  it('matches the page itself, a trailing slash, and pages under it', () => {
    expect(isCurrentPath('/directory', '/directory')).toBe(true)
    expect(isCurrentPath('/directory/', '/directory')).toBe(true)
    expect(isCurrentPath('/dms/new/u1', '/dms')).toBe(true)
  })
  it('does not match a sibling that only shares a prefix', () => {
    expect(isCurrentPath('/dmsx', '/dms')).toBe(false)
    expect(isCurrentPath('/invites', '/invite')).toBe(false)
    expect(isCurrentPath('/', '/directory')).toBe(false)
  })
})

describe('isCurrentGroup', () => {
  it('is true for every page of that group and no other', () => {
    expect(isCurrentGroup('/groups/g1/posts', 'g1')).toBe(true)
    expect(isCurrentGroup('/groups/g1/posts/p9', 'g1')).toBe(true)
    expect(isCurrentGroup('/groups/g1/settings', 'g1')).toBe(true)
    expect(isCurrentGroup('/groups/g10/posts', 'g1')).toBe(false)
    expect(isCurrentGroup('/groups/new', 'g1')).toBe(false)
  })
})

describe('link lists', () => {
  it('reach every screen the old Home buttons did', () => {
    const all = [...PLACE_LINKS, ...ACCOUNT_LINKS].map((l) => l.to).sort()
    expect(all).toEqual(
      [
        '/groups/new',
        '/invites',
        '/directory',
        '/dms',
        '/join-requests',
        '/appearance',
        '/account/password',
        '/account/rotate-keys',
        '/account/delete',
      ].sort(),
    )
  })
})
