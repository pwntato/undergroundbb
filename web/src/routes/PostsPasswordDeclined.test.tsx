import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { PostsPasswordDeclined } from './PostsPasswordDeclined'

describe('PostsPasswordDeclined', () => {
  it('shows the message, a button to ask again, and a way back to the groups', () => {
    const html = renderToStaticMarkup(
      createElement(
        MemoryRouter,
        null,
        createElement(PostsPasswordDeclined, {
          message: 'Needs your password.',
          onAskAgain: () => {},
        }),
      ),
    )
    expect(html).toContain('Needs your password.')
    expect(html).toContain('Enter password')
    expect(html).toMatch(/<a [^>]*href="\/"[^>]*>Back to your groups<\/a>/)
  })
})
