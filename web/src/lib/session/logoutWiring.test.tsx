// #224: wiring checks for logout that the pure-logic tests (runLogout.test.ts,
// nextRedirectDecision.test.ts) cannot see. The test environment is `node`
// with no DOM, so these render with react-dom/server: a context consumer
// captures the value SessionProvider builds during render, which is enough to
// call logout() without ever mounting effects.

import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { StaticRouter } from 'react-router'
import { SessionContext, type SessionState } from './session-context'

const clearLiveKeys = vi.fn()
vi.mock('@/lib/crypto/worker-client', () => ({
  clearLiveKeys: () => clearLiveKeys(),
  getOwnSigningKey: () => Promise.reject(new Error('not used')),
}))
vi.mock('@/lib/api/auth', () => ({
  getSession: () => new Promise(() => undefined),
}))

import { SessionProvider } from './SessionContext'
import { RequireAuth } from './RequireAuth'

beforeEach(() => {
  clearLiveKeys.mockClear()
})

function captureSession(): SessionState {
  const seen: SessionState[] = []
  renderToStaticMarkup(
    <SessionProvider>
      <SessionContext.Consumer>
        {(value) => {
          if (value !== undefined) seen.push(value)
          return null
        }}
      </SessionContext.Consumer>
    </SessionProvider>,
  )
  const session = seen[0]
  if (session === undefined) throw new Error('SessionProvider never rendered its child')
  return session
}

describe('SessionProvider.logout', () => {
  it("clears the crypto worker's live keys", () => {
    const session = captureSession()
    session.logout()
    expect(clearLiveKeys).toHaveBeenCalledTimes(1)
  })
})

describe('RequireAuth after logout', () => {
  function renderGuard(userId: string | null): string {
    const state: SessionState = {
      status: 'ready',
      userId,
      login: () => {},
      logout: () => {},
    }
    return renderToStaticMarkup(
      createElement(
        StaticRouter,
        { location: '/groups' },
        createElement(
          SessionContext.Provider,
          { value: state },
          createElement(RequireAuth, null, createElement('p', null, 'secret group list')),
        ),
      ),
    )
  }

  it('shows the protected content while a user is signed in', () => {
    expect(renderGuard('u1')).toContain('secret group list')
  })

  it('does not render the protected content once the user is gone', () => {
    // A static render turns <Navigate> into empty output, so the observable
    // part of "redirects to /login" here is that the content is not shown.
    expect(renderGuard(null)).toBe('')
  })
})
