import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { CreatePostPanel } from './CreatePostPanel'
import { elementsOf } from './elementTree.testkit'
import {
  DELETE_POST_QUESTION,
  GroupPostsPanel,
  PostControls,
  type PostListControls,
} from './GroupPostsPanel'
import { COPY_ADVISORY } from './editCopy'
import { authorLabel, postNotes, postTimeLabel } from './postNotes'
import type { PostEntry, PostView } from './runListPosts'

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

function controlsOf(over: Partial<PostListControls> = {}): PostListControls {
  return {
    selfUserId: 'u1',
    isAdmin: false,
    mode: { kind: 'idle' },
    busy: false,
    error: null,
    limits: { maxTitleBytes: 200, maxBodyBytes: 10000 },
    onEditOpen: () => {},
    onSave: () => {},
    onDeleteAsk: () => {},
    onDeleteConfirm: () => {},
    onClose: () => {},
    ...over,
  }
}

function render(
  posts: readonly PostEntry[],
  over: {
    loading?: boolean
    error?: string
    more?: boolean
    retry?: boolean
    controls?: Partial<PostListControls>
  } = {},
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
        ...(over.controls !== undefined && { controls: controlsOf(over.controls) }),
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

describe('GroupPostsPanel edited and deleted posts (#45)', () => {
  const editedContent = (timeSuspect: boolean) => ({
    kind: 'opened' as const,
    title: 'Hello',
    body: 'b',
    at: '2026-10-28T14:03:09.000Z',
    editedAt: '2026-10-30T09:12:00.000Z',
    timeSuspect,
  })

  it('marks an edited post, with the exact edit time in the tooltip', () => {
    const html = render([post({ signedDay: '2026-10-30', content: editedContent(false) })])
    expect(html).toContain(
      'alice · 2026-10-28 14:03 UTC · <span title="Edited 2026-10-30 09:12 UTC">edited</span>',
    )
  })

  it('shows no marker on a post never edited, even one whose row carries a signedDay', () => {
    expect(render([post({ signedDay: '2026-10-30' })])).not.toContain('edited')
  })

  it('names both days when an edited post has suspect times, and drops the edit time', () => {
    const p = post({ signedDay: '2026-10-30', content: editedContent(true) })
    const html = render([p])
    expect(html).toContain('· <span>edited</span>')
    expect(html).not.toContain('09:12')
    expect(postNotes(p)).toEqual([
      {
        tone: 'warn',
        text: "Suspect: the times inside this post do not match the day it is filed under (2026-10-28) and the day its edit was signed (2026-10-30), or the edit time is earlier than the post's own time, so its times are not shown.",
      },
    ])
  })

  it('shows a deleted post as a placeholder with no author, keeping the link to its comments', () => {
    const html = render([
      { deleted: true, sortKey: 'POST#2026-10-28#00112233445566aa', day: '2026-10-28' },
    ])
    expect(html).toContain('This post was deleted.')
    expect(html).not.toContain('alice')
    expect(html).not.toContain('an unknown member')
    expect(html).toContain('href="/groups/g1/posts/g1%232026-10-28%2300112233445566aa"')
  })
})

describe('Edit and Delete on a post (#45)', () => {
  const mine = post({ authorUserId: 'u1' })
  const theirs = post({ sortKey: 'POST#2026-10-28#00112233445566aa', authorUserId: 'u2' })
  const labels = (node: unknown) =>
    elementsOf(node as never)
      .map((e) => e.props['children'])
      .filter((c) => typeof c === 'string')
  const buttons = (p: PostView, over: Partial<PostListControls> = {}) =>
    labels(PostControls({ post: p, controls: controlsOf(over) }))
  const click = (tree: unknown, label: string) =>
    (
      elementsOf(tree as never).find((e) => e.props['children'] === label)!.props[
        'onClick'
      ] as () => void
    )()

  it("offers Edit and Delete on the reader's own post, and nothing on another member's", () => {
    expect(buttons(mine)).toEqual(['Edit', 'Delete'])
    expect(buttons(theirs)).toEqual([])
    expect(PostControls({ post: theirs, controls: controlsOf() })).toBeNull()
  })

  it("gives an admin Delete, but not Edit, on another member's post", () => {
    expect(buttons(theirs, { isAdmin: true })).toEqual(['Delete'])
  })

  it('offers no Edit on an unreadable post (no text to start from), only Delete', () => {
    expect(buttons(post({ content: { kind: 'unreadable' } }))).toEqual(['Delete'])
  })

  it('shows no buttons where the screen passes no controls, and renders them under each post in the whole panel', () => {
    expect(render([mine])).not.toContain('>Edit<')
    const html = render([mine, theirs], { controls: {} })
    expect(html.match(/>Edit</g)).toHaveLength(1)
    expect(html.match(/>Delete</g)).toHaveLength(1)
  })

  it("calls the handlers with the post's sort key and current title and body", () => {
    const calls: string[] = []
    const tree = PostControls({
      post: mine,
      controls: controlsOf({
        onEditOpen: (k, t, b) => calls.push(`edit ${k} ${JSON.stringify([t, b])}`),
        onDeleteAsk: (k) => calls.push(`delete ${k}`),
      }),
    })
    click(tree, 'Edit')
    click(tree, 'Delete')
    expect(calls).toEqual([
      `edit ${mine.sortKey} ${JSON.stringify(['Hello', 'First line\nSecond line'])}`,
      `delete ${mine.sortKey}`,
    ])
  })

  it('disables both buttons while a send is in flight', () => {
    const tree = PostControls({ post: mine, controls: controlsOf({ busy: true }) })
    const bs = elementsOf(tree).filter((e) => typeof e.props['children'] === 'string')
    expect(bs).toHaveLength(2)
    for (const b of bs) expect(b.props['disabled']).toBe(true)
  })

  it('shows the edit form seeded with the post, with the advisory, Save, and Save waiting until something differs', () => {
    const calls: [string, string][] = []
    const tree = PostControls({
      post: mine,
      controls: controlsOf({
        mode: { kind: 'editing', sortKey: mine.sortKey, title: 'Hello', body: 'old' },
        onSave: (t, b) => calls.push([t, b]),
      }),
    })
    const form = elementsOf(tree).find((e) => e.type === CreatePostPanel)!.props
    expect(form['initial']).toEqual({ title: 'Hello', body: 'old' })
    expect(form['unchangedFrom']).toEqual({ title: 'Hello', body: 'old' })
    expect(form['hint']).toBe(COPY_ADVISORY)
    expect(COPY_ADVISORY).toBe('Any member may have kept a copy of the original.')
    expect(form['submitLabel']).toBe('Save')
    expect(form['idPrefix']).toBe(`edit-${mine.sortKey}`)
    ;(form['onSubmit'] as (t: string, b: string) => void)('t2', 'b2')
    expect(calls).toEqual([['t2', 'b2']])
  })

  it('shows the confirmation with the question, the advisory, and Delete and Cancel', () => {
    const calls: string[] = []
    const tree = PostControls({
      post: mine,
      controls: controlsOf({
        mode: { kind: 'confirmDelete', sortKey: mine.sortKey },
        onDeleteConfirm: () => calls.push('confirm'),
        onClose: () => calls.push('close'),
      }),
    })
    const html = renderToStaticMarkup(tree)
    expect(html).toContain(DELETE_POST_QUESTION)
    expect(DELETE_POST_QUESTION).toBe(
      'Delete this post? Its comments stay, but nothing new can be added.',
    )
    expect(html).toContain('Any member may have kept a copy of the original.')
    click(tree, 'Delete')
    click(tree, 'Cancel')
    expect(calls).toEqual(['confirm', 'close'])
  })

  it('shows a failure inside the form it belongs to, and an idle one at the top of the page', () => {
    const inConfirm = render([mine], {
      controls: {
        mode: { kind: 'confirmDelete', sortKey: mine.sortKey },
        error: 'Could not delete',
      },
    })
    expect(inConfirm.match(/Could not delete/g)).toHaveLength(1)
    const idle = render([mine], { controls: { error: 'This post is gone' } })
    expect(idle.match(/This post is gone/g)).toHaveLength(1)
  })

  it('only opens the form on the post it is for', () => {
    const other = post({ sortKey: 'POST#2026-10-28#00112233445566bb', authorUserId: 'u1' })
    const html = render([mine, other], {
      controls: { mode: { kind: 'editing', sortKey: other.sortKey, title: 'x', body: 'y' } },
    })
    expect(html.match(/>Save</g)).toHaveLength(1)
    expect(html.match(/>Edit</g)).toHaveLength(1)
  })

  it('shows no controls on a deleted post', () => {
    const html = render(
      [{ deleted: true, sortKey: 'POST#2026-10-28#00112233445566cc', day: '2026-10-28' }],
      {
        controls: {},
      },
    )
    expect(html).not.toContain('>Edit<')
    expect(html).not.toContain('>Delete<')
  })
})
