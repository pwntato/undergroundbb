import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { GroupPostsPanel } from './GroupPostsPanel'
import { authorLabel, postNotes, postTimeLabel } from './postNotes'
import type { PostView } from './runListPosts'

function post(over: Partial<PostView> = {}): PostView {
  return {
    sortKey: 'POST#2026-10-28#00112233445566ff',
    day: '2026-10-28',
    authorUserId: 'u1',
    authorName: 'alice',
    content: {
      kind: 'opened',
      title: 'Hello',
      body: 'First line\nSecond line',
      at: '2026-10-28T14:03:09.000Z',
      timeSuspect: false,
    },
    signature: { kind: 'valid' },
    keyAnchor: 'pinned',
    ...over,
  }
}

function render(
  posts: readonly PostView[],
  over: { loading?: boolean; error?: string; more?: boolean; retry?: boolean } = {},
) {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(GroupPostsPanel, {
        groupId: 'g1',
        posts,
        loading: over.loading ?? false,
        error: over.error ?? null,
        hasMore: over.more ?? false,
        onLoadMore: () => {},
        ...(over.retry === true && { onRetry: () => {} }),
      }),
    ),
  )
}

describe('GroupPostsPanel', () => {
  it('shows the title, author, time and body of an opened post, with no status line when all is well', () => {
    const html = render([post()])
    expect(html).toContain('Hello')
    expect(html).toContain('alice · 2026-10-28 14:03 UTC')
    expect(html).toContain('First line\nSecond line')
    expect(html).toContain('whitespace-pre-wrap')
    expect(postNotes(post())).toEqual([])
  })

  it('renders markup in a title or body as text, never as markup, a link or an image', () => {
    const evil =
      '<img src="https://evil.example/x.png" onerror="alert(1)"><a href="https://evil.example">click</a><script>alert(1)</script>'
    const html = render([
      post({
        content: {
          kind: 'opened',
          title: evil,
          body: `${evil}\n[link](https://evil.example) ![i](https://evil.example/i.png)`,
          at: '2026-10-28T14:03:09.000Z',
          timeSuspect: false,
        },
      }),
    ])
    expect(html).not.toContain('<img')
    expect(html).not.toContain('<script')
    expect(html).not.toContain('href="https://evil.example')
    expect(html).not.toContain('src="https://evil.example')
    expect(html).toContain('&lt;img src=')
    expect(html).toContain('&lt;script&gt;')
    // Only the links the page itself owns: the post's Comments, Write a post, Back to your groups.
    expect(html.match(/<a /g)?.length).toBe(3)
  })

  it('says an unopened post could not be opened, hides nothing else, and blames no one', () => {
    const p = post({ content: { kind: 'unreadable' } })
    const html = render([p])
    expect(html).toContain('This post could not be opened.')
    expect(html).not.toContain('Hello')
    const text = postNotes(p)
      .map((n) => n.text)
      .join(' ')
    expect(text).not.toMatch(/alice|signature|forged|tamper|author|wrote/i)
    expect(postNotes(p)).toHaveLength(1)
  })

  it('warns when the signature check failed, naming who it may not be from', () => {
    const notes = postNotes(post({ signature: { kind: 'invalid' } }))
    expect(notes).toEqual([
      { tone: 'warn', text: 'Signature check failed: this may not have been written by alice.' },
    ])
  })

  it('says it could not check, with the reason, when the author’s keys were not vouched for', () => {
    const notes = postNotes(
      post({
        signature: { kind: 'unchecked', reason: 'their keys changed since you saved them' },
      }),
    )
    expect(notes).toEqual([
      {
        tone: 'muted',
        text: 'Could not check who wrote this: their keys changed since you saved them.',
      },
    ])
    expect(notes[0]!.text).not.toMatch(/failed|invalid/i)
  })

  it('flags a time that is not on the filed day, and does not show that time', () => {
    const p = post({
      content: {
        kind: 'opened',
        title: 'T',
        body: 'b',
        at: '2026-10-30T01:00:00.000Z',
        timeSuspect: true,
      },
    })
    expect(postNotes(p)[0]!.text).toContain('Suspect')
    expect(postNotes(p)[0]!.text).toContain('2026-10-28')
    expect(postTimeLabel(p)).toBe('2026-10-28')
    expect(render([p])).not.toContain('2026-10-30')
  })

  it('tells the reader when an author’s keys were saved for the first time', () => {
    const notes = postNotes(post({ keyAnchor: 'first-seen' }))
    expect(notes).toHaveLength(1)
    expect(notes[0]!.text).toContain('First time you have seen alice')
  })

  it('names an author it could not read without inventing a name', () => {
    expect(authorLabel(post({ authorName: null }))).toBe('an unknown member')
  })

  it('does not call a short page the end: empty with a cursor offers more instead of "No posts yet"', () => {
    const html = render([], { more: true })
    expect(html).not.toContain('No posts yet.')
    expect(html).toContain('Older posts may follow.')
    expect(html).toContain('Load older posts')
  })

  it('shows the empty state, the error, loading, and the load-more button only when they apply', () => {
    expect(render([])).toContain('No posts yet.')
    expect(render([], { error: 'Boom' })).toContain('Boom')
    expect(render([], { error: 'Boom' })).not.toContain('No posts yet.')
    expect(render([], { loading: true })).toContain('Loading…')
    expect(render([post()], { more: true })).toContain('Load older posts')
    expect(render([post()], { more: true, loading: true })).not.toContain('Load older posts')
    expect(render([post()])).not.toContain('Load older posts')
  })

  it('links to writing a post and back to the groups', () => {
    const html = render([])
    expect(html).toContain('href="/groups/g1/posts/new"')
    expect(html).toContain('href="/"')
  })

  it('offers Try again only when asked to, and not while loading', () => {
    expect(render([], { error: 'Failed' })).not.toContain('Try again')
    expect(render([], { error: 'Failed', retry: true })).toContain('Try again')
    expect(render([], { error: 'Failed', retry: true, loading: true })).not.toContain('Try again')
  })

  it('links each post to its thread, with the # of the post id as %23, and not for a malformed key', () => {
    const html = render([post()])
    expect(html).toContain('href="/groups/g1/posts/g1%232026-10-28%2300112233445566ff"')
    expect(html).toContain('>Comments</a>')
    expect(render([post({ sortKey: 'garbage' })])).not.toContain('>Comments</a>')
  })
})
