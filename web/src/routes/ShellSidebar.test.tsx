import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { elementsOf } from './elementTree.testkit'
import type { DisplayGroup } from './runListGroups'
import { ShellFrame, ShellSidebar, type ShellSidebarProps } from './ShellSidebar'

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

function props(o: Partial<ShellSidebarProps> = {}): ShellSidebarProps {
  return {
    load: { status: 'ready', groups: [group()] },
    usernames: new Map(),
    requestReauth: () => {},
    pathname: '/',
    loggingOut: false,
    logoutError: null,
    onLogout: () => Promise.resolve(),
    ...o,
  }
}

const render = (p: ShellSidebarProps) =>
  renderToStaticMarkup(createElement(MemoryRouter, null, createElement(ShellSidebar, p)))

describe('ShellSidebar', () => {
  it('links each group to its posts, with the unread count named for a screen reader', () => {
    const html = render(
      props({
        load: {
          status: 'ready',
          groups: [group({ unread: 3 }), group({ groupId: 'g2', displayName: 'Roof' })],
        },
      }),
    )
    expect(html).toContain('href="/groups/g1/posts"')
    expect(html).toContain('href="/groups/g2/posts"')
    expect(html).toContain('Book Club')
    expect(html).toContain('(3 unread notifications)')
  })

  it('marks only the open group as the current page', () => {
    const html = render(
      props({
        pathname: '/groups/g2/members',
        load: { status: 'ready', groups: [group(), group({ groupId: 'g2', displayName: 'Roof' })] },
      }),
    )
    expect(html.match(/aria-current="page"/g)).toHaveLength(1)
    expect(html).toMatch(/aria-current="page"[^>]*>(<span[^>]*>)?Roof/)
  })

  it('keeps every old Home destination reachable, plus Log out', () => {
    const html = render(props())
    for (const to of [
      '/groups/new',
      '/directory',
      '/invites',
      '/join-requests',
      '/dms',
      '/appearance',
      '/account/password',
      '/account/rotate-keys',
      '/account/delete',
    ])
      expect(html).toContain(`href="${to}"`)
    expect(html).toContain('Log out')
  })

  it('says what to do when there are no groups, and while loading or failed', () => {
    expect(render(props({ load: { status: 'ready', groups: [] } }))).toContain('None yet')
    expect(render(props({ load: { status: 'loading' } }))).toContain('Loading your groups')
    expect(render(props({ load: { status: 'error' } }))).toContain('Couldn&#x27;t load')
  })

  it('offers the password step only when a private name is cold, and its click calls requestReauth', () => {
    expect(render(props())).not.toContain('Enter your password')
    const requestReauth = vi.fn()
    const p = props({
      requestReauth,
      load: { status: 'ready', groups: [group({ nameStatus: 'coldKeys', displayName: null })] },
    })
    expect(render(p)).toContain('Enter your password')
    const button = elementsOf(ShellSidebar(p)).find(
      (e) => e.type === 'button' && String(e.props['children']).includes('Enter your password'),
    )
    expect(button).toBeDefined()
    ;(button!.props['onClick'] as () => void)()
    expect(requestReauth).toHaveBeenCalledOnce()
  })

  it('shows a failed logout', () => {
    expect(render(props({ logoutError: 'Could not log out' }))).toContain('Could not log out')
  })
})

describe('ShellFrame', () => {
  const frame = (open: boolean, onToggle = () => {}) =>
    ShellFrame({ open, onToggle, sidebar: 'SIDE', children: 'PAGE' })

  it('hides the nav on a phone until the menu is opened, and always shows it from md up', () => {
    const closed = renderToStaticMarkup(frame(false))
    const open = renderToStaticMarkup(frame(true))
    expect(closed).toMatch(/<nav[^>]*class="hidden [^"]*md:block/)
    expect(open).toMatch(/<nav[^>]*class="block [^"]*md:block/)
    expect(closed).toContain('aria-expanded="false"')
    expect(open).toContain('aria-expanded="true"')
    expect(closed).toContain('aria-controls="app-nav"')
    expect(closed).toContain('id="app-nav"')
  })

  it('the menu button calls onToggle', () => {
    const onToggle = vi.fn()
    const button = elementsOf(frame(false, onToggle)).find((e) => e.type === 'button')
    expect(button).toBeDefined()
    ;(button!.props['onClick'] as () => void)()
    expect(onToggle).toHaveBeenCalledOnce()
  })
})
