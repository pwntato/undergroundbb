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

  it('seeds the fields from initial, so a re-login does not lose the draft', () => {
    const html = render({ initial: { title: 'My title', body: 'Half-written body' } })
    expect(html).toContain('value="My title"')
    expect(html).toContain('Half-written body')
    expect(html).toContain('8 / 200 bytes')
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

describe('CreatePostPanel as an edit form (#45)', () => {
  const from = { title: 'Hello', body: 'World' }
  const edit = (over: Partial<Parameters<typeof CreatePostPanel>[0]> = {}) =>
    render({
      initial: from,
      unchangedFrom: from,
      idPrefix: 'edit-x',
      submitLabel: 'Save',
      busyLabel: 'Saving…',
      hint: 'Any member may have kept a copy of the original.',
      onCancel: () => {},
      ...over,
    })

  it('says Save, shows the hint and Cancel, and uses its own field ids', () => {
    const html = edit()
    expect(html).toContain('>Save<')
    expect(html).not.toContain('>Post</button>')
    expect(html).toContain('Any member may have kept a copy of the original.')
    expect(html).toContain('>Cancel<')
    expect(html).toContain('id="edit-x-title"')
    expect(html).toContain('id="edit-x-body"')
  })

  it('disables Save until the text differs from what the form was opened with', () => {
    expect(edit()).toMatch(/<button[^>]*type="submit"[^>]*disabled=""/)
  })

  it('says Saving… and disables Cancel while sending', () => {
    const html = edit({ posting: true })
    expect(html).toContain('Saving…')
    expect(html).toMatch(
      /<button[^>]*type="button"[^>]*disabled=""[^>]*>Cancel|<button[^>]*disabled=""[^>]*type="button"[^>]*>Cancel/,
    )
  })

  it('keeps the create form as it was: Post, no Cancel, no hint', () => {
    const html = render()
    expect(html).toContain('>Post</button>')
    expect(html).not.toContain('>Cancel<')
    expect(html).toContain('id="post-title"')
  })
})
