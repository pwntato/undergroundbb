import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { CreatePostPanel } from './CreatePostPanel'

const LIMITS = { maxTitleBytes: 200, maxBodyBytes: 10000 }

function render(over: Partial<Parameters<typeof CreatePostPanel>[0]> = {}): string {
  return renderToStaticMarkup(
    <CreatePostPanel
      limits={LIMITS}
      posting={false}
      message={null}
      error={null}
      onSubmit={() => {}}
      {...over}
    />,
  )
}

describe('CreatePostPanel', () => {
  it('shows the limits in bytes and says the post is plain text', () => {
    const html = render()
    expect(html).toContain('0 / 200 bytes')
    expect(html).toContain('0 / 10000 bytes')
    expect(html).toContain('Plain text only')
  })

  it('follows the configured limits', () => {
    const html = render({ limits: { maxTitleBytes: 80, maxBodyBytes: 500 } })
    expect(html).toContain('0 / 80 bytes')
    expect(html).toContain('0 / 500 bytes')
  })

  it('disables Post until there is a title', () => {
    expect(render()).toMatch(/<button[^>]*disabled[^>]*>Post</)
  })

  it('shows success and error messages', () => {
    expect(render({ message: 'Posted.' })).toContain('Posted.')
    expect(render({ error: 'The server rejected the post.' })).toContain(
      'The server rejected the post.',
    )
  })

  it('locks the form while posting', () => {
    const html = render({ posting: true })
    expect(html).toContain('Posting…')
    expect(html).toMatch(/<textarea[^>]*disabled/)
  })
})
