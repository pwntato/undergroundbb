// The presentational half of GroupPostsScreen -- #43. Prop-driven, so it can be
// tested with renderToStaticMarkup (see GroupList.tsx's header). The screen owns
// loading; runListPosts.ts owns opening and checking.
//
// Plain text only, always: a title or body is put on the page as a React text
// node and nothing else -- never as markup, never as a link, never as an image
// source -- so nothing a member writes can load anything into another member's
// view (docs/DESIGN.md, "Posts"). The line breaks the author typed are kept by
// CSS (whitespace-pre-wrap), not by interpreting the text.

import { Link } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Data } from '@/components/ui/data'
import { CreatePostPanel } from './CreatePostPanel'
import { COPY_ADVISORY } from './editCopy'
import type { PostControlMode } from './postControls'
import type { PostLimits } from './runCreatePost'
import { postIdOf } from '@/lib/crypto/post-check'
import { authorLabel, DELETED_POST_TEXT, editedMark, postNotes, postTimeLabel } from './postNotes'
import { isDeletedPost, type PostEntry, type PostView } from './runListPosts'

/** The question asked before a post is deleted. */
export const DELETE_POST_QUESTION =
  'Delete this post? Its comments stay, but nothing new can be added.'

/** What Edit and Delete on a post need from the screen; absent where they make no sense. */
export interface PostListControls {
  /** The reader, whose own posts get Edit and Delete. */
  readonly selfUserId: string
  /** An admin may delete anyone's post. */
  readonly isAdmin: boolean
  readonly mode: PostControlMode
  readonly busy: boolean
  readonly error: string | null
  readonly limits: PostLimits
  readonly onEditOpen: (sortKey: string, title: string, body: string) => void
  /** Save pressed on the edit form, with what is in it. */
  readonly onSave: (title: string, body: string) => void
  /** The edit form's text changed. */
  readonly onDraft: (title: string, body: string) => void
  readonly onDeleteAsk: (sortKey: string) => void
  readonly onDeleteConfirm: () => void
  readonly onClose: () => void
}

/** Edit and Delete for one post, or the form either of them opened (#45). */
export function PostControls({
  post,
  controls,
}: {
  readonly post: PostView
  readonly controls: PostListControls
}) {
  const mine = post.authorUserId === controls.selfUserId
  // An unreadable post has no text to start from and no original time to keep.
  const opened = post.content.kind === 'opened' ? post.content : null
  const canEdit = mine && opened !== null
  const canDelete = mine || controls.isAdmin
  if (!canEdit && !canDelete) return null
  const { mode, busy, error } = controls
  if (mode.kind === 'editing' && mode.sortKey === post.sortKey) {
    return (
      <CreatePostPanel
        limits={controls.limits}
        posting={busy}
        message={null}
        error={error}
        onSubmit={controls.onSave}
        initial={mode.draft ?? { title: mode.title, body: mode.body }}
        unchangedFrom={{ title: mode.title, body: mode.body }}
        onDraft={controls.onDraft}
        idPrefix={`edit-${post.sortKey}`}
        submitLabel="Save"
        busyLabel="Saving…"
        hint={COPY_ADVISORY}
        onCancel={controls.onClose}
      />
    )
  }
  if (mode.kind === 'confirmDelete' && mode.sortKey === post.sortKey) {
    return (
      <div className="flex flex-col gap-1.5">
        {error !== null && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <p className="text-sm font-medium">{DELETE_POST_QUESTION}</p>
        <p className="text-xs text-muted-foreground">{COPY_ADVISORY}</p>
        <div className="flex gap-2">
          <Button
            type="button"
            variant="destructive"
            disabled={busy}
            onClick={controls.onDeleteConfirm}
          >
            {busy ? 'Deleting…' : 'Delete'}
          </Button>
          <Button type="button" variant="outline" disabled={busy} onClick={controls.onClose}>
            Cancel
          </Button>
        </div>
      </div>
    )
  }
  return (
    <div className="flex gap-1">
      {canEdit && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={busy}
          onClick={() => {
            controls.onEditOpen(post.sortKey, opened.title, opened.body)
          }}
        >
          Edit
        </Button>
      )}
      {canDelete && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={busy}
          onClick={() => {
            controls.onDeleteAsk(post.sortKey)
          }}
        >
          Delete
        </Button>
      )}
    </div>
  )
}

export function GroupPostsPanel({
  groupId,
  posts,
  loading,
  error,
  hasMore,
  onLoadMore,
  onRetry,
  controls,
}: {
  readonly groupId: string
  readonly posts: readonly PostEntry[]
  readonly loading: boolean
  readonly error: string | null
  readonly hasMore: boolean
  readonly onLoadMore: () => void
  /** Set when the first page failed and there is nothing yet to load more from. */
  readonly onRetry?: (() => void) | undefined
  readonly controls?: PostListControls | undefined
}) {
  return (
    <div className="flex w-full max-w-xl flex-col gap-4 text-left">
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {controls !== undefined && controls.mode.kind === 'idle' && controls.error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{controls.error}</AlertDescription>
        </Alert>
      )}
      {posts.length === 0 && !loading && error === null && !hasMore && (
        <p className="text-sm text-muted-foreground">No posts yet.</p>
      )}
      {posts.length === 0 && !loading && error === null && hasMore && (
        <p className="text-sm text-muted-foreground">
          No posts to show here yet. Older posts may follow.
        </p>
      )}
      {posts.map((post) =>
        isDeletedPost(post) ? (
          // Its comments stay readable, so the link stays; who wrote it is not served.
          <article key={post.sortKey} className="flex flex-col gap-1.5 rounded-md border px-3 py-2">
            <p className="text-sm italic text-muted-foreground">{DELETED_POST_TEXT}</p>
            <PostCommentsLink groupId={groupId} sortKey={post.sortKey} title={undefined} />
          </article>
        ) : (
          <PostCard key={post.sortKey} groupId={groupId} post={post} controls={controls} />
        ),
      )}
      {onRetry !== undefined && !loading && (
        <Button type="button" variant="outline" onClick={onRetry}>
          Try again
        </Button>
      )}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {hasMore && !loading && (
        <Button type="button" variant="outline" onClick={onLoadMore}>
          Load older posts
        </Button>
      )}
      <Link
        to={`/groups/${groupId}/posts/new`}
        className="text-sm text-primary underline-offset-4 hover:underline"
      >
        Write a post
      </Link>
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </div>
  )
}

/** A post as shown: title, who and when, body, and what to know about its trust. Shared with the thread page (#318). */
export function PostContent({ post }: { readonly post: PostView }) {
  const edited = post.content.kind === 'opened' ? editedMark(post.content) : null
  return (
    <>
      {post.content.kind === 'opened' && (
        <h2 className="break-words text-base font-semibold">{post.content.title}</h2>
      )}
      <p className="text-xs text-muted-foreground">
        <Data>{authorLabel(post)}</Data> · <Data>{postTimeLabel(post)}</Data>
        {edited !== null && (
          <>
            {' · '}
            <span title={edited.title}>{edited.text}</span>
          </>
        )}
      </p>
      {post.content.kind === 'opened' && post.content.body !== '' && (
        <p className="whitespace-pre-wrap break-words text-sm">{post.content.body}</p>
      )}
      {postNotes(post).map((note) => (
        <p
          key={note.text}
          className={`text-xs ${note.tone === 'warn' ? 'text-destructive' : 'text-muted-foreground'}`}
        >
          {note.text}
        </p>
      ))}
    </>
  )
}

function PostCard({
  groupId,
  post,
  controls,
}: {
  readonly groupId: string
  readonly post: PostView
  readonly controls: PostListControls | undefined
}) {
  return (
    <article className="flex flex-col gap-1.5 rounded-md border px-3 py-2">
      <PostContent post={post} />
      <PostCommentsLink
        groupId={groupId}
        sortKey={post.sortKey}
        title={post.content.kind === 'opened' ? post.content.title : undefined}
      />
      {controls !== undefined && <PostControls post={post} controls={controls} />}
    </article>
  )
}

/** Opens the post's thread. The `#`s in the post id travel as %23; the title rides along for display only. */
function PostCommentsLink({
  groupId,
  sortKey,
  title,
}: {
  readonly groupId: string
  readonly sortKey: string
  readonly title: string | undefined
}) {
  const postId = postIdOf(groupId, sortKey)
  if (postId === undefined) return null
  return (
    <Link
      to={`/groups/${groupId}/posts/${encodeURIComponent(postId)}`}
      state={title !== undefined ? { postTitle: title } : undefined}
      className="text-sm text-primary underline-offset-4 hover:underline"
    >
      Comments
    </Link>
  )
}
