import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { AppHeaderLink } from './AppHeader'

function render(total?: { unread: number; unreadMore: boolean } | null): string {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(AppHeaderLink, total === undefined ? {} : { total }),
    ),
  )
}

describe('AppHeaderLink', () => {
  it('is the plain link with no count, a zero count, or a failed fetch', () => {
    for (const html of [render(), render(null), render({ unread: 0, unreadMore: false })]) {
      expect(html).toContain('href="/notifications"')
      expect(html).toContain('Notifications')
      expect(html).not.toContain('rounded-full')
      expect(html).not.toContain('unread')
    }
  })

  it('shows the count as a badge inside the link, with a screen reader sentence', () => {
    const html = render({ unread: 3, unreadMore: false })
    expect(html).toContain('href="/notifications"')
    expect(html).toContain('>3</span>')
    expect(html).toContain('(3 unread notifications)')
  })

  it('says 99+ for a lower bound, and the singular for one', () => {
    expect(render({ unread: 99, unreadMore: true })).toContain('>99+</span>')
    const one = render({ unread: 1, unreadMore: false })
    expect(one).toContain('(1 unread notification)')
    expect(one).not.toContain('notifications)')
  })
})
