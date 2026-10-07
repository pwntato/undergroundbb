import { describe, expect, it } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { SuccessorMessages } from './SuccessorMessages'

const html = (message: string | null, error: string | null) =>
  renderToStaticMarkup(createElement(SuccessorMessages, { message, error }))

describe('SuccessorMessages', () => {
  it('renders nothing without a message or an error', () => {
    expect(html(null, null)).toBe('')
  })

  it('shows the message and the error', () => {
    const out = html('Saved.', 'Refused.')
    expect(out).toContain('Saved.')
    expect(out).toContain('Refused.')
  })

  it('keeps the messages out of the layout flow, so the buttons above do not move', () => {
    expect(html('Saved.', null)).toMatch(/^<div class="absolute top-full[^"]*">/)
  })
})
