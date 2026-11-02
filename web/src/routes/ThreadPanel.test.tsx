import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { MemoryRouter } from 'react-router'
import { describe, expect, it } from 'vitest'
import { ReactionBar } from './ReactionBar'
import { elementsOf } from './elementTree.testkit'
import {
  COPY_ADVISORY,
  CommentControls,
  DELETE_QUESTION,
  ThreadPanel,
  type ThreadControls,
  type ThreadPost,
  type ThreadReactions,
  type ThreadReply,
} from './ThreadPanel'
import { ReplyBox } from './ReplyBox'
import type { PostListControls } from './GroupPostsPanel'
import type { PostEntry, PostView } from './runListPosts'
import type { CommentView, ReactionView, ThreadEntry } from './runLoadThread'
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

function controlsOf(over: Partial<ThreadControls> = {}): ThreadControls {
  return {
    selfUserId: 'u1',
    isAdmin: false,
    readOnly: false,
    mode: { kind: 'idle' },
    busy: false,
    error: null,
    maxBytes: 100,
    onEditOpen: () => {},
    onDraft: () => {},
    onSave: () => {},
    onDeleteAsk: () => {},
    onDeleteConfirm: () => {},
    onClose: () => {},
    ...over,
  }
}

function render(
  comments: readonly ThreadEntry[],
  over: {
    loading?: boolean
    error?: string
    more?: boolean
    retry?: boolean
    title?: string
    reply?: Partial<ThreadReply>
    reactions?: Partial<ThreadReactions>
    controls?: Partial<ThreadControls>
    post?: ThreadPost
    postProblem?: string
  } = {},
) {
  return renderToStaticMarkup(
    createElement(
      MemoryRouter,
      null,
      createElement(ThreadPanel, {
        groupId: 'g1',
        postTitle: over.title,
        post: over.post,
        postProblem: over.postProblem,
        comments,
        loading: over.loading ?? false,
        error: over.error ?? null,
        hasMore: over.more ?? false,
        onLoadMore: () => {},
        ...(over.retry === true && { onRetry: () => {} }),
        ...(over.reactions !== undefined && {
          reactions: {
            reactions: [],
            selfUserId: 'me',
            reacting: [],
            error: null,
            notice: null,
            ready: true,
            readOnly: false,
            onPress: () => {},
            ...over.reactions,
          },
        }),
        ...(over.controls !== undefined && { controls: controlsOf(over.controls) }),
        ...(over.reply !== undefined && {
          reply: {
            replyTo: null,
            draft: '',
            maxBytes: 100,
            sending: false,
            error: null,
            notice: null,
            onOpen: () => {},
            onEdit: () => {},
            onSend: () => {},
            ...over.reply,
          },
        }),
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

describe('ThreadPanel reply box', () => {
  const deep = Array(8).fill('0001').join('.')

  it('has no reply controls when the screen passes none', () => {
    const html = render([comment()])
    expect(html).not.toContain('Reply')
    expect(html).not.toContain('<textarea')
  })

  it('shows a Reply button per comment and one top-level box at the bottom', () => {
    const html = render([comment(), comment({ path: '0002' })], { reply: {} })
    expect(html.match(/>Reply</g)).toHaveLength(2)
    expect(html.match(/<textarea/g)).toHaveLength(1)
    expect(html).toContain('Add a comment')
    expect(html).toContain('0 / 100 bytes. Plain text only.')
  })

  it('asks for the first comment on an empty thread', () => {
    expect(render([], { reply: {} })).toContain('Write the first comment')
  })

  it('moves the box under the comment being replied to, and keeps the draft in it', () => {
    const html = render([comment(), comment({ path: '0002' })], {
      reply: { replyTo: '0001', draft: 'my draft' },
    })
    expect(html.match(/<textarea/g)).toHaveLength(1)
    expect(html).toContain('Your reply')
    expect(html).not.toContain('Add a comment')
    expect(html).toContain('my draft')
    // The comment with the box open has no Reply button; the other one does.
    expect(html.match(/>Reply</g)).toHaveLength(1)
    expect(html.indexOf('Your reply')).toBeGreaterThan(html.indexOf('First line'))
    expect(html).toContain('>Cancel<')
  })

  it('says where a reply to a comment at the depth cap will appear', () => {
    const at = comment({ path: deep, depth: 8 })
    const html = render([at], { reply: { replyTo: deep } })
    expect(html).toContain('will appear beside this comment')
    expect(render([comment()], { reply: { replyTo: '0001' } })).not.toContain('beside')
  })

  it('falls back to the bottom box when the target is not on the page', () => {
    const html = render([comment()], { reply: { replyTo: '0042' } })
    expect(html).toContain('Add a comment')
    expect(html).not.toContain('Your reply')
  })

  it('shows the notice, the error and the byte count, and flags a draft over the limit', () => {
    const html = render([comment()], {
      reply: { notice: 'Comment sent.', error: 'It failed.', draft: '€'.repeat(40), maxBytes: 100 },
    })
    expect(html).toContain('Comment sent.')
    expect(html).toContain('It failed.')
    expect(html).toContain('120 / 100 bytes')
    expect(html).toContain('The comment is too long.')
    expect(html).toContain('disabled=""')
  })

  it('disables the box and the Reply buttons while sending', () => {
    const html = render([comment(), comment({ path: '0002' })], {
      reply: { sending: true, draft: 'x' },
    })
    expect(html).toContain('Sending…')
    expect(html).not.toMatch(/<button type="button"[^>]*>Reply</)
  })

  it('offers no Reply on a comment whose path is malformed', () => {
    const html = render([comment({ path: 'junk', depth: 0 })], { reply: {} })
    expect(html).not.toContain('>Reply<')
  })
})

describe('ThreadPanel reactions (#46)', () => {
  const rx = (target: string, reactorUserId: string, index: number | null): ReactionView => ({
    target,
    reactorUserId,
    index,
  })
  const groups = (html: string) => html.match(/aria-label="Reactions to [^"]*"/g) ?? []

  it('shows no reaction buttons where the screen gives none', () => {
    expect(groups(render([comment()]))).toEqual([])
  })

  it('shows a row for the post and one under each comment', () => {
    const html = render(
      [comment(), comment({ path: '0001.0001', depth: 2 }), comment({ path: '0002' })],
      { reactions: {} },
    )
    expect(groups(html)).toEqual([
      'aria-label="Reactions to the post"',
      'aria-label="Reactions to this comment"',
      'aria-label="Reactions to this comment"',
      'aria-label="Reactions to this comment"',
    ])
  })

  it("keeps the post's row out until the first page is in", () => {
    const html = render([], { reactions: { ready: false } })
    expect(groups(html)).toEqual([])
  })

  it('gives a comment with a malformed path no row, since it cannot be reacted to', () => {
    const html = render([comment({ path: 'x', depth: 0 })], { reactions: { ready: false } })
    expect(groups(html)).toEqual([])
  })

  it('counts each row from its own target only', () => {
    const html = render([comment(), comment({ path: '0002' })], {
      reactions: {
        reactions: [rx('0000', 'a', 1), rx('0001', 'a', 2), rx('0001', 'b', 2), rx('0002', 'a', 3)],
      },
    })
    const rows = html.split('role="group"').slice(1)
    expect(rows).toHaveLength(3)
    expect(rows[0]).toContain('Thumbs up, 1 reaction')
    expect(rows[0]).toContain('Heart, 0 reactions')
    expect(rows[1]).toContain('Heart, 2 reactions')
    expect(rows[1]).not.toContain('Thumbs up, 1 reaction')
    expect(rows[2]).toContain('Laughing, 1 reaction')
  })

  it('disables every reaction button, and keeps the counts, when the thread is read-only', () => {
    const html = render([comment(), comment({ path: '0002' })], {
      reactions: { reactions: [rx('0002', 'me', 6)], readOnly: true },
    })
    const rows = html.split('role="group"').slice(1)
    expect(rows).toHaveLength(3)
    for (const row of rows) expect(row).toContain(' disabled=""')
    expect(rows[2]).toContain('Celebrate, 1 reaction, yours')
    expect(render([comment()], { reactions: {} })).not.toContain(' disabled=""')
  })

  it("presses the reader's own and disables only the target being saved", () => {
    const html = render([comment(), comment({ path: '0002' })], {
      reactions: { reactions: [rx('0002', 'me', 6)], reacting: ['0002'] },
    })
    const rows = html.split('role="group"').slice(1)
    expect(rows[2]).toContain('Celebrate, 1 reaction, yours')
    expect(rows[2]).toContain(' disabled=""')
    expect(rows[0]).not.toContain(' disabled=""')
    expect(rows[1]).not.toContain(' disabled=""')
  })

  it('says a page-wide notice once, above the rows, and says nothing without one', () => {
    const html = render([comment()], {
      reactions: { notice: 'The comment you reacted to is gone.' },
    })
    expect(html.match(/The comment you reacted to is gone\./g)).toHaveLength(1)
    expect(html.indexOf('The comment you reacted to is gone.')).toBeLessThan(
      html.indexOf('role="group"'),
    )
    expect(render([comment()], { reactions: {} })).not.toContain('is gone')
  })

  it('shows a failure under the target it happened on, and nowhere else', () => {
    const html = render([comment(), comment({ path: '0002' })], {
      reactions: { error: { target: '0002', message: 'Could not save your reaction.' } },
    })
    const rows = html.split('role="group"').slice(1)
    expect(rows[2]).toContain('Could not save your reaction.')
    expect(rows[0]).not.toContain('Could not save')
    expect(rows[1]).not.toContain('Could not save')
  })
})

describe('ThreadPanel reports reaction presses', () => {
  it('names the target and the button pressed, for the post and for each comment', () => {
    const calls: [string, number][] = []
    const tree = ThreadPanel({
      groupId: 'g1',
      comments: [comment(), comment({ path: '0001.0001', depth: 2 })],
      loading: false,
      error: null,
      hasMore: false,
      onLoadMore: () => {},
      reactions: {
        reactions: [],
        selfUserId: 'me',
        reacting: [],
        error: null,
        notice: null,
        ready: true,
        readOnly: false,
        onPress: (target, index) => calls.push([target, index]),
      },
    })
    const bars = elementsOf(tree).filter((e) => e.type === ReactionBar)
    expect(bars).toHaveLength(3)
    bars.forEach((bar, i) => (bar.props['onPress'] as (n: number) => void)(i + 3))
    expect(calls).toEqual([
      ['0000', 3],
      ['0001', 4],
      ['0001.0001', 5],
    ])
  })
})

describe('ThreadPanel edited and deleted comments (#45)', () => {
  const editedContent = (timeSuspect: boolean) => ({
    kind: 'opened' as const,
    text: 'changed',
    at: '2026-10-29T14:03:09.000Z',
    editedAt: '2026-10-31T08:15:00.000Z',
    timeSuspect,
  })

  it('marks an edited comment, with the exact edit time in the tooltip', () => {
    const html = render([comment({ signedDay: '2026-10-31', content: editedContent(false) })])
    expect(html).toContain(
      'alice · 2026-10-29 14:03 UTC · <span title="Edited 2026-10-31 08:15 UTC">edited</span>',
    )
  })

  it('shows no marker on a comment never edited', () => {
    expect(render([comment()])).not.toContain('edited')
  })

  it('keeps the marker but drops the edit time when the times are suspect', () => {
    const c = comment({ signedDay: '2026-10-31', content: editedContent(true) })
    const html = render([c])
    expect(html).toContain('· <span>edited</span>')
    expect(html).not.toContain('08:15')
    expect(commentNotes(c)).toEqual([
      {
        tone: 'warn',
        text: "Suspect: the edit time inside this comment is not on the day the edit was signed (2026-10-31), or is earlier than the comment's own time, so its times are not shown.",
      },
    ])
  })

  it('shows a deleted comment as a placeholder with no author, time, reactions or Reply, indented in place', () => {
    const html = render(
      [
        comment(),
        { deleted: true, path: '0001.0001', depth: 2 },
        comment({ path: '0001.0001.0001', depth: 3 }),
      ],
      { reactions: {}, reply: {} },
    )
    expect(html).toContain('This comment was deleted.')
    const placeholder = /<article data-depth="2"[^>]*>(.*?)<\/article>/.exec(html)
    expect(placeholder?.[0]).toContain('margin-left:1rem')
    expect(placeholder?.[1]).toBe(
      '<p class="text-sm italic text-muted-foreground">This comment was deleted.</p>',
    )
    // A row for the post and one per live comment; Reply on the live ones only.
    expect(html.match(/aria-label="Reactions to [^"]*"/g)).toHaveLength(3)
    expect(html.match(/>Reply</g)).toHaveLength(2)
  })
})

describe('Edit and Delete on a comment (#45)', () => {
  const mine = comment({ authorUserId: 'u1' })
  const theirs = comment({ path: '0002', authorUserId: 'u2' })
  const labels = (node: unknown) =>
    elementsOf(node as never)
      .filter((e) => e.type === 'button' || typeof e.type === 'function')
      .map((e) => e.props['children'])
      .filter((c) => typeof c === 'string')
  const buttons = (c: ReturnType<typeof comment>, over: Partial<ThreadControls> = {}) =>
    labels(CommentControls({ comment: c, controls: controlsOf(over) }))

  it("offers Edit and Delete on the reader's own comment, and nothing on another member's", () => {
    expect(buttons(mine)).toEqual(['Edit', 'Delete'])
    expect(buttons(theirs)).toEqual([])
    expect(CommentControls({ comment: theirs, controls: controlsOf() })).toBeNull()
  })

  it("gives an admin Delete, but not Edit, on another member's comment", () => {
    expect(buttons(theirs, { isAdmin: true })).toEqual(['Delete'])
  })

  it('hides Edit on a read-only thread but keeps Delete', () => {
    expect(buttons(mine, { readOnly: true })).toEqual(['Delete'])
  })

  it('offers no Edit on an unreadable comment (no text to start from), only Delete', () => {
    const unreadable = comment({ content: { kind: 'unreadable' } })
    expect(buttons(unreadable)).toEqual(['Delete'])
  })

  it('shows no buttons where the screen passes no controls', () => {
    const html = render([mine])
    expect(html).not.toContain('>Edit<')
    expect(html).not.toContain('>Delete<')
  })

  it('renders the controls under the comment in the whole panel', () => {
    const html = render([mine, theirs], { controls: {} })
    expect(html.match(/>Edit</g)).toHaveLength(1)
    expect(html.match(/>Delete</g)).toHaveLength(1)
  })

  it("calls the handlers with the comment's path and current text", () => {
    const calls: string[] = []
    const tree = CommentControls({
      comment: mine,
      controls: controlsOf({
        onEditOpen: (p, t) => calls.push(`edit ${p} ${JSON.stringify(t)}`),
        onDeleteAsk: (p) => calls.push(`delete ${p}`),
      }),
    })
    const click = (label: string) =>
      (
        elementsOf(tree).find((e) => e.props['children'] === label)!.props['onClick'] as () => void
      )()
    click('Edit')
    click('Delete')
    expect(calls).toEqual([`edit 0001 ${JSON.stringify('First line\nSecond line')}`, 'delete 0001'])
  })

  it('disables both buttons while a send is in flight', () => {
    const tree = CommentControls({ comment: mine, controls: controlsOf({ busy: true }) })
    const bs = elementsOf(tree).filter((e) => typeof e.props['children'] === 'string')
    expect(bs).toHaveLength(2)
    for (const b of bs) expect(b.props['disabled']).toBe(true)
  })

  it('shows the edit form with the advisory, a Save button, and Save waiting until the text changes', () => {
    const open = (draft: string) =>
      elementsOf(
        CommentControls({
          comment: mine,
          controls: controlsOf({ mode: { kind: 'editing', path: '0001', draft, original: 'old' } }),
        }),
      ).find((e) => e.type === ReplyBox)!.props
    const same = open('old')
    expect(same['label']).toBe('Edit your comment')
    expect(same['hint']).toBe(COPY_ADVISORY)
    expect(same['hint']).toBe('Any member may have kept a copy of the original.')
    expect(same['submitLabel']).toBe('Save')
    expect(same['unchanged']).toBe(true)
    expect(open('new')['unchanged']).toBe(false)
  })

  it('shows the confirmation with the question, the advisory, and Delete and Cancel', () => {
    const calls: string[] = []
    const tree = CommentControls({
      comment: mine,
      controls: controlsOf({
        mode: { kind: 'confirmDelete', path: '0001' },
        onDeleteConfirm: () => calls.push('confirm'),
        onClose: () => calls.push('close'),
      }),
    })
    const html = renderToStaticMarkup(tree)
    expect(html).toContain('Delete this comment? Replies stay.')
    expect(DELETE_QUESTION).toBe('Delete this comment? Replies stay.')
    expect(html).toContain('Any member may have kept a copy of the original.')
    const click = (label: string) =>
      (
        elementsOf(tree).find((e) => e.props['children'] === label)!.props['onClick'] as () => void
      )()
    click('Delete')
    click('Cancel')
    expect(calls).toEqual(['confirm', 'close'])
  })

  it('shows a failure inside the form it belongs to, and an idle one at the top of the page', () => {
    const inForm = render([mine], {
      controls: { mode: { kind: 'confirmDelete', path: '0001' }, error: 'Could not delete' },
    })
    expect(inForm.match(/Could not delete/g)).toHaveLength(1)
    const idle = render([mine], { controls: { error: 'This post was deleted' } })
    expect(idle.match(/This post was deleted/g)).toHaveLength(1)
  })

  it('only opens the form on the comment it is for', () => {
    const html = render([mine, comment({ path: '0003', authorUserId: 'u1' })], {
      controls: { mode: { kind: 'editing', path: '0003', draft: 'x', original: 'y' } },
    })
    expect(html.match(/Edit your comment/g)).toHaveLength(1)
    expect(html.match(/>Edit</g)).toHaveLength(1)
  })

  it('shows no controls on a deleted comment', () => {
    const html = render([{ deleted: true, path: '0001', depth: 1 }], { controls: {} })
    expect(html).not.toContain('>Edit<')
    expect(html).not.toContain('>Delete<')
  })
})

describe('the post at the top of the thread (#318)', () => {
  const postView = (over: Partial<PostView> = {}): PostView => ({
    sortKey: 'POST#2026-10-28#00112233445566ff',
    day: '2026-10-28',
    authorUserId: 'u1',
    authorName: 'alice',
    content: {
      kind: 'opened',
      title: 'Hello there',
      body: 'Post line one\nline two',
      at: '2026-10-28T14:03:09.000Z',
      timeSuspect: false,
    },
    signature: { kind: 'valid' },
    keyAnchor: 'pinned',
    ...over,
  })
  const postControls = (over: Partial<PostListControls> = {}): PostListControls => ({
    selfUserId: 'u1',
    isAdmin: false,
    mode: { kind: 'idle' },
    busy: false,
    error: null,
    limits: { maxTitleBytes: 100, maxBodyBytes: 1000 },
    onEditOpen: () => {},
    onSave: () => {},
    onDeleteAsk: () => {},
    onDeleteConfirm: () => {},
    onClose: () => {},
    ...over,
  })
  const withPost = (entry: PostEntry, over: Partial<PostListControls> = {}): ThreadPost => ({
    entry,
    controls: postControls(over),
  })
  const buttonLabels = (html: string) =>
    [...html.matchAll(/<button[^>]*>([^<]*)<\/button>/g)].map((m) => m[1])

  it('shows the post itself, with who wrote it, instead of the "On:" line', () => {
    const html = render([], { title: 'From the list', post: withPost(postView()) })
    expect(html).toContain('Hello there')
    expect(html).toContain('Post line one\nline two')
    expect(html).toContain('alice')
    expect(html).not.toContain('On: ')
  })

  it('keeps the "On:" line until the post has loaded', () => {
    expect(render([], { title: 'From the list' })).toContain('On: From the list')
  })

  it("offers Edit and Delete on the reader's own post, Delete alone to an admin, nothing to others", () => {
    expect(buttonLabels(render([], { post: withPost(postView()) }))).toEqual(['Edit', 'Delete'])
    const theirs = postView({ authorUserId: 'u2' })
    expect(buttonLabels(render([], { post: withPost(theirs) }))).toEqual([])
    expect(buttonLabels(render([], { post: withPost(theirs, { isAdmin: true }) }))).toEqual([
      'Delete',
    ])
  })

  it('shows a deleted post as a placeholder with no author and no buttons', () => {
    const html = render([], {
      post: withPost({
        deleted: true,
        sortKey: 'POST#2026-10-28#00112233445566ff',
        day: '2026-10-28',
      }),
    })
    expect(html).toContain('This post was deleted.')
    expect(html).not.toContain('alice')
    expect(buttonLabels(html)).toEqual([])
  })

  it('says why a failed action stopped, once, when no form is open', () => {
    const html = render([], { post: withPost(postView(), { error: 'This post is gone.' }) })
    expect(html.split('This post is gone.')).toHaveLength(2)
  })

  it('puts the delete question inside the post, not above the comments', () => {
    const html = render([], {
      post: withPost(postView(), { mode: { kind: 'confirmDelete', sortKey: postView().sortKey } }),
    })
    expect(html).toContain('Delete this post? Its comments stay, but nothing new can be added.')
    expect(buttonLabels(html)).toEqual(['Delete', 'Cancel'])
  })

  it('says why the post is missing when it could not be loaded', () => {
    const html = render([], { postProblem: 'Couldn’t load the post itself.' })
    expect(html).toContain('Couldn’t load the post itself.')
  })
})
