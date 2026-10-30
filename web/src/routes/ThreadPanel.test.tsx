import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { ThreadPanel } from './ThreadPanel'
import type { CommentView } from './runLoadThread'
import { commentAuthorLabel, commentNotes, commentTimeLabel } from './threadNotes'

function comment(over: Partial<CommentView> = {}): CommentView {
  return {
    path: '0001',
    depth: 1,
    authorUserId: 'u1',
    authorName: 'alice',
    signedDay: '2026-10-29',
    content: {
      kind: 'opened',
      text: 'First line\nSecond line',
      at: '2026-10-29T14:03:09.000Z',
      timeSuspect: false,
    },
    signature: { kind: 'valid' },
    keyAnchor: 'pinned',
    ...over,
  }
}

function render(
  comments: readonly CommentView[],
  over: {
    loading?: boolean
    error?: string
    more?: boolean
    retry?: boolean
    title?: string
  } = {},
) {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(ThreadPanel, {
        groupId: 'g1',
        postTitle: over.title,
        comments,
        loading: over.loading ?? false,
        error: over.error ?? null,
        hasMore: over.more ?? false,
        onLoadMore: () => {},
        ...(over.retry === true && { onRetry: () => {} }),
      }),
    ),
  )
}

describe('ThreadPanel', () => {
  it('shows the author, time and text of a comment, with no status line when all is well', () => {
    const html = render([comment()])
    expect(html).toContain('alice · 2026-10-29 14:03 UTC')
    expect(html).toContain('First line\nSecond line')
    expect(html).toContain('whitespace-pre-wrap')
    expect(commentNotes(comment())).toEqual([])
  })

  it('renders markup in a comment as text, never as markup, a link or an image', () => {
    const evil =
      '<img src=x onerror=alert(1)><a href="https://evil.example">x</a><script>1</script>'
    const html = render([
      comment({
        content: { kind: 'opened', text: evil, at: '2026-10-29T14:03:09.000Z', timeSuspect: false },
      }),
    ])
    expect(html).not.toContain('<img')
    expect(html).not.toContain('<script')
    expect(html).not.toContain('evil.example"')
    expect(html).toContain('&lt;img src=x onerror=alert(1)&gt;')
    expect((html.match(/<a /g) ?? []).length).toBe(1) // only the "Back to posts" link
  })

  it('indents replies by depth and caps the indent', () => {
    const html = render([
      comment({ path: '0001', depth: 1 }),
      comment({ path: '0001.0001', depth: 2 }),
      comment({ path: '0001.0001.0001.0001.0001.0001.0001.0001', depth: 8 }),
    ])
    expect(html).toContain('data-depth="1" style="margin-left:0rem"')
    expect(html).toContain('data-depth="2" style="margin-left:1rem"')
    expect(html).toContain('data-depth="8" style="margin-left:4rem"')
  })

  it('names the post when the list passed its title along, and not otherwise', () => {
    expect(render([], { title: 'Lunch plans' })).toContain('On: Lunch plans')
    expect(render([])).not.toContain('On:')
  })

  it('says there are no comments only when there is nothing more to load', () => {
    expect(render([])).toContain('No comments yet.')
    const more = render([], { more: true })
    expect(more).not.toContain('No comments yet.')
    expect(more).toContain('More may follow.')
    expect(more).toContain('Load more comments')
  })

  it('offers loading more only while idle and not alongside a retry', () => {
    expect(render([comment()], { more: true })).toContain('Load more comments')
    expect(render([comment()], { more: true, loading: true })).not.toContain('Load more comments')
    const retry = render([comment()], { more: true, retry: true, error: 'Nope' })
    expect(retry).toContain('Try again')
    expect(retry).not.toContain('Load more comments')
    expect(retry).toContain('Nope')
  })

  it('links back to the group posts', () => {
    expect(render([])).toContain('href="/groups/g1/posts"')
  })
})

describe('commentNotes', () => {
  it('blames no one for a comment that will not open', () => {
    const notes = commentNotes(comment({ content: { kind: 'unreadable' } }))
    expect(notes).toHaveLength(1)
    expect(notes[0]!.tone).toBe('muted')
    expect(notes[0]!.text).not.toContain('alice')
  })

  it('warns on a failed signature and names the claimed author', () => {
    expect(commentNotes(comment({ signature: { kind: 'invalid' } }))).toEqual([
      {
        tone: 'warn',
        text: 'Signature check failed: this may not have been written by alice.',
      },
    ])
  })

  it('says why a check could not be made', () => {
    expect(
      commentNotes(
        comment({ signature: { kind: 'unchecked', reason: 'their keys could not be read' } }),
      ),
    ).toEqual([
      { tone: 'muted', text: 'Could not check who wrote this: their keys could not be read.' },
    ])
  })

  it('notes a first sight of keys and a suspect time, and hides a suspect time', () => {
    const c = comment({
      keyAnchor: 'first-seen',
      content: { kind: 'opened', text: 'x', at: '2026-01-01T00:00:00.000Z', timeSuspect: true },
    })
    expect(commentNotes(c).map((n) => n.tone)).toEqual(['muted', 'warn'])
    expect(commentTimeLabel(c)).toBe('2026-10-29')
  })

  it('labels an author whose profile could not be read', () => {
    expect(commentAuthorLabel(comment({ authorName: null }))).toBe('an unknown member')
  })
})
