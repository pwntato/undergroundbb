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
import { postIdOf } from '@/lib/crypto/post-check'
import { authorLabel, DELETED_POST_TEXT, editedMark, postNotes, postTimeLabel } from './postNotes'
import { isDeletedPost, type PostEntry, type PostView } from './runListPosts'

export function GroupPostsPanel({
  groupId,
  posts,
  loading,
  error,
  hasMore,
  onLoadMore,
  onRetry,
}: {
  readonly groupId: string
  readonly posts: readonly PostEntry[]
  readonly loading: boolean
  readonly error: string | null
  readonly hasMore: boolean
  readonly onLoadMore: () => void
  /** Set when the first page failed and there is nothing yet to load more from. */
  readonly onRetry?: (() => void) | undefined
}) {
  return (
    <div className="flex w-full max-w-xl flex-col gap-4 text-left">
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
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
          <PostCard key={post.sortKey} groupId={groupId} post={post} />
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

function PostCard({ groupId, post }: { readonly groupId: string; readonly post: PostView }) {
  const edited = post.content.kind === 'opened' ? editedMark(post.content) : null
  return (
    <article className="flex flex-col gap-1.5 rounded-md border px-3 py-2">
      {post.content.kind === 'opened' && (
        <h2 className="break-words text-base font-semibold">{post.content.title}</h2>
      )}
      <p className="text-xs text-muted-foreground">
        {authorLabel(post)} · {postTimeLabel(post)}
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
      <PostCommentsLink
        groupId={groupId}
        sortKey={post.sortKey}
        title={post.content.kind === 'opened' ? post.content.title : undefined}
      />
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
