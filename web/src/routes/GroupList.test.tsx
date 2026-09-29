// Matches SignupProgressStep.test.tsx's established pattern for a
// prop-driven component in this no-jsdom test suite: renderToStaticMarkup
// is enough here since GroupList takes a plain LoadState and renders
// synchronously, with no effects to exercise -- the one piece of real
// context it now needs is react-router's, for the per-group "Invite" link
// (issue #38), so this wraps in a bare MemoryRouter rather than a real
// BrowserRouter/history -- nothing here ever actually navigates.

import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { GroupList, type LoadState } from './GroupList'
import { groupLabel } from './groupLabel'
import type { DisplayGroup } from './runListGroups'

function render(load: LoadState): string {
  return renderToStaticMarkup(createElement(MemoryRouter, null, createElement(GroupList, { load })))
}

function displayGroup(overrides: Partial<DisplayGroup> = {}): DisplayGroup {
  return {
    groupId: 'group-1',
    visibility: 'public',
    role: 'member',
    generation: 0,
    nameGeneration: 0,
    displayName: 'Book Club',
    displayDescription: 'We read books',
    nameStatus: 'plaintext',
    ...overrides,
  }
}

describe('groupLabel', () => {
  it('shows the decrypted/plaintext name for plaintext and decrypted groups', () => {
    expect(groupLabel(displayGroup({ nameStatus: 'plaintext', displayName: 'Book Club' }))).toBe(
      'Book Club',
    )
    expect(groupLabel(displayGroup({ nameStatus: 'decrypted', displayName: 'Roof Group' }))).toBe(
      'Roof Group',
    )
  })

  it('falls back to a placeholder for an unreadable group rather than an empty string', () => {
    expect(groupLabel(displayGroup({ nameStatus: 'unreadable', displayName: null }))).toBe(
      '(unreadable group)',
    )
  })

  it('shows a distinct placeholder for a coldKeys group', () => {
    expect(groupLabel(displayGroup({ nameStatus: 'coldKeys', displayName: null }))).toBe(
      '(private group)',
    )
  })
})

describe('GroupList', () => {
  it('shows a loading message', () => {
    const html = render({ status: 'loading' })
    expect(html).toContain('Loading your groups')
  })

  it('shows an error message', () => {
    const html = render({ status: 'error' })
    expect(html).toContain('Couldn')
    expect(html).toContain('reloading the page')
  })

  it('shows an empty-state message for a ready, empty list', () => {
    const html = render({ status: 'ready', groups: [] })
    expect(html).toContain('You&#x27;re not in any groups yet')
  })

  it('renders every group with its name and role', () => {
    const groups = [
      displayGroup({ groupId: 'g1', displayName: 'Book Club', role: 'admin' }),
      displayGroup({
        groupId: 'g2',
        visibility: 'private',
        nameStatus: 'decrypted',
        displayName: 'Roof Group',
        role: 'member',
      }),
    ]
    const html = render({ status: 'ready', groups })
    expect(html).toContain('Book Club')
    expect(html).toContain('admin')
    expect(html).toContain('Roof Group')
    expect(html).toContain('member')
  })

  it('renders an unreadable private group with a fallback label, alongside a normal one', () => {
    const groups = [
      displayGroup({ groupId: 'g-good', displayName: 'Good Group', nameStatus: 'decrypted' }),
      displayGroup({
        groupId: 'g-bad',
        visibility: 'private',
        displayName: null,
        nameStatus: 'unreadable',
      }),
    ]
    const html = render({ status: 'ready', groups })
    expect(html).toContain('Good Group')
    expect(html).toContain('(unreadable group)')
  })

  // Issue #38: only an Admin or Ambassador may create an invite (the
  // server's own 403 is the real authorization check -- this just governs
  // whether the link is offered at all).
  it('shows the Invite link for an admin or ambassador, not for a plain member', () => {
    const groups = [
      displayGroup({ groupId: 'g-admin', role: 'admin' }),
      displayGroup({ groupId: 'g-ambassador', role: 'ambassador' }),
      displayGroup({ groupId: 'g-member', role: 'member' }),
    ]
    const html = render({ status: 'ready', groups })

    expect(html).toContain('/groups/g-admin/invite')
    expect(html).toContain('/groups/g-ambassador/invite')
    expect(html).not.toContain('/groups/g-member/invite')
  })

  it('shows the "log in again" hint only when at least one group is coldKeys', () => {
    const withoutColdKeys = render({
      status: 'ready',
      groups: [displayGroup({ nameStatus: 'plaintext' })],
    })
    expect(withoutColdKeys).not.toContain('Log in again')

    const withColdKeys = render({
      status: 'ready',
      groups: [displayGroup({ visibility: 'private', displayName: null, nameStatus: 'coldKeys' })],
    })
    expect(withColdKeys).toContain('Log in again to see private group names')
  })

  it('links every group to its settings screen, whatever the role', () => {
    const html = render({
      status: 'ready',
      groups: [
        displayGroup({ groupId: 'a', role: 'member' }),
        displayGroup({ groupId: 'b', role: 'admin' }),
      ],
    })
    expect(html).toContain('href="/groups/a/settings"')
    expect(html).toContain('href="/groups/b/settings"')
  })
})
