import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { HomePanel } from './HomePanel'
import type { LoadState } from './GroupList'
import type { DisplayGroup } from './runListGroups'

function group(o: Partial<DisplayGroup> = {}): DisplayGroup {
  return {
    groupId: 'g1',
    visibility: 'public',
    role: 'member',
    generation: 0,
    noRotation: true,
    nameGeneration: 0,
    displayName: 'Book Club',
    displayDescription: '',
    nameStatus: 'plaintext',
    ...o,
  }
}
const render = (load: LoadState) =>
  renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(HomePanel, { load, usernames: new Map(), onReauthenticate: () => {} }),
    ),
  )

describe('HomePanel', () => {
  it('tells a user with no groups the three ways in, with a link for each', () => {
    const html = render({ status: 'ready', groups: [] })
    expect(html).toContain('nothing to read')
    expect(html).toContain('href="/groups/new"')
    expect(html).toContain('href="/directory"')
    expect(html).toContain('href="/invites"')
    expect(html).not.toContain('all caught up')
  })

  it('says all caught up when no group has unread, and names the ones that do', () => {
    const quiet = render({ status: 'ready', groups: [group()] })
    expect(quiet).toContain('all caught up')
    expect(quiet).not.toContain('nothing to read')
    const busy = render({
      status: 'ready',
      groups: [group({ unread: 2 }), group({ groupId: 'g2', displayName: 'Roof' })],
    })
    expect(busy).toContain('New to read in Book Club.')
    expect(busy).not.toContain('all caught up')
  })

  it('shows neither empty state while loading or after a failure', () => {
    for (const load of [{ status: 'loading' }, { status: 'error' }] as const) {
      const html = render(load)
      expect(html).not.toContain('nothing to read')
      expect(html).not.toContain('caught up')
    }
  })
})
