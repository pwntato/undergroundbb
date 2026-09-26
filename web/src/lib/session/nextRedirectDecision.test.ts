// Pins the bug caught in review on #32's own PR: RedirectIfAuthenticated
// must decide exactly once and never revisit that decision, however
// session.userId changes afterward -- see RedirectIfAuthenticated.tsx's own
// header comment for the concrete failure (SignupScreen's mid-flow
// session.login() call losing the recovery code).

import { describe, expect, it } from 'vitest'
import { nextRedirectDecision } from './nextRedirectDecision'

describe('nextRedirectDecision (issue #32 review fix)', () => {
  it('stays pending while status is loading', () => {
    expect(nextRedirectDecision('pending', 'loading', null)).toBe('pending')
  })

  it('decides redirect once status is ready and userId is set', () => {
    expect(nextRedirectDecision('pending', 'ready', 'user-1')).toBe('redirect')
  })

  it('decides allow once status is ready and userId is null', () => {
    expect(nextRedirectDecision('pending', 'ready', null)).toBe('allow')
  })

  it('never re-decides away from redirect, even if userId later becomes null', () => {
    // Symmetric with the allow case below: once decided, never revisited.
    // In practice a latched 'redirect' unmounts the component (it renders
    // <Navigate>), so this exact input can't occur through RedirectIfAuthenticated
    // itself -- but nextRedirectDecision's own contract shouldn't rely on
    // that; the guard is `current !== 'pending'`, not `current !== 'pending'
    // && current !== 'redirect'`, so this case is still worth pinning
    // directly against the function.
    expect(nextRedirectDecision('redirect', 'ready', null)).toBe('redirect')
  })

  it('never re-decides away from allow, even if userId later becomes non-null', () => {
    // This is the regression itself: SignupScreen calls session.login(userId)
    // mid-flow, well before it's done showing the recovery code. Once this
    // guard has already allowed SignupScreen to render, a later userId must
    // not flip the decision to 'redirect' and unmount it.
    expect(nextRedirectDecision('allow', 'ready', 'user-1')).toBe('allow')
  })
})
