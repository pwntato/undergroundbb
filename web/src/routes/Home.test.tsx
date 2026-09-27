// Matches SignupProgressStep.test.tsx's established renderToStaticMarkup
// pattern. renderToStaticMarkup never runs effects (this is SSR, not a real
// mount), so Home's own useEffect-driven fetch/decrypt never fires here --
// that data-fetching logic is runListGroups.ts's own job and is covered
// directly in runListGroups.test.ts; GroupList.test.tsx covers every
// LoadState's rendering. This file covers only what's left in Home itself:
// the two states SessionContext controls before any effect could run --
// 'loading' (renders nothing) and logged-out (the unchanged signup/login
// prompt) -- via a real SessionContext.Provider, not a mock of useSession.

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { StaticRouter } from 'react-router'
import { SessionContext, type SessionState } from '@/lib/session/session-context'
import { Home } from './Home'

// Home renders react-router <Link>s, which need a router context to resolve
// even during a static (no-navigation) render -- StaticRouter is the SSR-
// appropriate one, needing no browser history/location APIs this `node`
// test environment doesn't have.
function renderWithSession(session: SessionState): string {
  return renderToStaticMarkup(
    createElement(
      StaticRouter,
      { location: '/' },
      createElement(SessionContext.Provider, { value: session }, createElement(Home)),
    ),
  )
}

function sessionState(overrides: Partial<SessionState> = {}): SessionState {
  return {
    status: 'ready',
    userId: null,
    login: () => {},
    logout: () => {},
    ...overrides,
  }
}

describe('Home', () => {
  it('renders nothing while the session bootstrap is still loading', () => {
    const html = renderWithSession(sessionState({ status: 'loading' }))
    expect(html).toBe('')
  })

  it('shows the signup/login prompt for a logged-out session, unchanged from #33', () => {
    const html = renderWithSession(sessionState({ status: 'ready', userId: null }))
    expect(html).toContain('Frontend scaffold')
    expect(html).toContain('Sign up')
    expect(html).toContain('Log in')
    // Must not show any group-list chrome for a logged-out visitor.
    expect(html).not.toContain('Loading your groups')
    expect(html).not.toContain('Create a group')
  })

  it('shows the create-group link and no signup/login prompt once logged in', () => {
    // renderToStaticMarkup renders the FIRST pass before useEffect ever
    // runs, so this is Home's initial 'loading' LoadState for an
    // authenticated session -- proving the logged-in branch (group list +
    // Create a group / Change password) renders at all, not the full fetch
    // flow, which is runListGroups.test.ts's job.
    const html = renderWithSession(sessionState({ status: 'ready', userId: 'user-1' }))
    expect(html).toContain('Loading your groups')
    expect(html).toContain('Create a group')
    expect(html).toContain('Change password')
    expect(html).not.toContain('Frontend scaffold')
  })
})
