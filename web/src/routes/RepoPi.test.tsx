// #395: the floating π shows on every page except the signed-out landing page, which has the
// worded link instead. Rendered through a real StaticRouter and SessionContext, like Home.test.tsx.

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { StaticRouter } from 'react-router'
import { SessionContext, type SessionState } from '@/lib/session/session-context'
import { REPO_URL, repoPiShown } from './repoLink'
import { RepoPi } from './RepoPi'

function session(status: 'loading' | 'ready', userId: string | null): SessionState {
  return { status, userId, login: () => {}, logout: () => {} }
}

function render(location: string, s: SessionState): string {
  return renderToStaticMarkup(
    createElement(
      StaticRouter,
      { location },
      createElement(SessionContext.Provider, { value: s }, createElement(RepoPi)),
    ),
  )
}

describe('repoPiShown', () => {
  const signedOut = session('ready', null)
  const signedIn = session('ready', 'user-1')
  const loading = session('loading', null)

  it('hides on the signed-out landing page, with or without a trailing slash', () => {
    expect(repoPiShown('/', signedOut)).toBe(false)
    expect(repoPiShown('', signedOut)).toBe(false)
  })

  it('hides on / while the session is loading, so it does not flash before the landing page', () => {
    expect(repoPiShown('/', loading)).toBe(false)
  })

  it("shows on a signed-in member's home at /", () => {
    expect(repoPiShown('/', signedIn)).toBe(true)
  })

  it('shows on every other page, signed in, signed out or loading', () => {
    for (const path of [
      '/login',
      '/signup',
      '/recovery',
      '/account/password',
      '/groups/g1/posts/p1',
      '/invites/abc',
    ]) {
      expect(repoPiShown(path, signedOut), path).toBe(true)
      expect(repoPiShown(path, signedIn), path).toBe(true)
      expect(repoPiShown(path, loading), path).toBe(true)
    }
  })
})

describe('RepoPi', () => {
  it('renders nothing on the signed-out landing page', () => {
    expect(render('/', session('ready', null))).toBe('')
  })

  it('renders a fixed, labelled link to the repo that opens a new tab without a referrer', () => {
    const html = render('/groups/g1/posts', session('ready', 'user-1'))
    expect(html).toContain(`href="${REPO_URL}"`)
    expect(html).toContain('target="_blank"')
    expect(html).toContain('rel="noopener noreferrer"')
    expect(html).toContain('aria-label="UndergroundBB source code on GitHub"')
    expect(html).toMatch(/class="[^"]*\bfixed\b/)
    expect(html).toContain('>π</a>')
  })

  it("renders on a signed-in member's home at /", () => {
    expect(render('/', session('ready', 'user-1'))).toContain('>π</a>')
  })
})
