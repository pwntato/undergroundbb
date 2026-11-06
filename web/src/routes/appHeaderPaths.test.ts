import { describe, expect, it } from 'vitest'
import { headerShownOn } from './appHeaderPaths'

describe('headerShownOn', () => {
  it('hides the header on every screen that shows a recovery code once', () => {
    for (const path of ['/signup', '/recovery', '/account/password', '/account/rotate-keys']) {
      expect(headerShownOn(path), path).toBe(false)
    }
  })

  it('hides it on a trailing slash or a sub-path of those routes', () => {
    expect(headerShownOn('/signup/')).toBe(false)
    expect(headerShownOn('/account/password/')).toBe(false)
    expect(headerShownOn('/account/rotate-keys/step')).toBe(false)
  })

  it('shows it everywhere else, including routes that merely start the same way', () => {
    for (const path of [
      '/',
      '/notifications',
      '/invites',
      '/account/delete',
      '/groups/abc/posts',
      '/signups',
      '/recovery-codes',
      '/account/passwords',
    ]) {
      expect(headerShownOn(path), path).toBe(true)
    }
  })
})
