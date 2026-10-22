import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { MemoryRouter } from 'react-router'
import { renderToStaticMarkup } from 'react-dom/server'
import { RotateKeysReview, type ReviewGroup } from './RotateKeysReview'

function render(
  groups: ReviewGroup[],
  extra: { invitesToRevoke?: number; awaiting?: number; error?: string | null } = {},
): string {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(RotateKeysReview, {
        groups,
        invitesToRevoke: extra.invitesToRevoke ?? 0,
        invitesAwaitingCompletion: extra.awaiting ?? 0,
        error: extra.error ?? null,
        onSubmit: () => undefined,
      }),
    ),
  )
}

const g = (id: string, label: string, open = false): ReviewGroup => ({ groupId: id, label, open })

describe('RotateKeysReview', () => {
  it('tells rotating apart from changing a password, and links to the cheap one', () => {
    const html = render([])
    expect(html).toContain('not the same as changing your password')
    expect(html).toContain('href="/account/password"')
  })

  it('lists the groups the user administers and flags the Open ones', () => {
    const html = render([g('1', 'Book Club'), g('2', 'Town Square', true)])
    expect(html).toContain('Book Club')
    expect(html).toContain('Town Square (Open)')
    expect(html).not.toContain('Book Club (Open)')
    expect(html).toContain('whoever holds your old keys can keep reading it')
  })

  it('shows no Open warning when no group is Open', () => {
    expect(render([g('1', 'Book Club')])).not.toContain('can keep reading it')
  })

  it('says so when the user administers nothing', () => {
    expect(render([])).toContain('do not administer any groups')
  })

  it('says what happens to sent invites, both kinds', () => {
    const html = render([], { invitesToRevoke: 2, awaiting: 1 })
    expect(html).toContain('(2) will be cancelled')
    expect(html).toContain('(1) cannot be cancelled')
    expect(render([])).not.toContain('will be cancelled')
  })

  it('keeps the submit button disabled until the user confirms', () => {
    expect(render([])).toMatch(/<button[^>]*disabled[^>]*>Rotate my keys/)
  })

  it('shows a server-side error', () => {
    expect(render([], { error: 'Nothing was rotated.' })).toContain('Nothing was rotated.')
  })

  it('does not say this tab is signed out, because it stays signed in', () => {
    const html = render([])
    expect(html).toContain('This tab stays signed in')
    expect(html).not.toMatch(/—|--/)
  })
})
