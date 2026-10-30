// The presentational half of ThreadScreen -- #44. Prop-driven, so it can be
// tested with renderToStaticMarkup (see GroupPostsPanel.tsx's header). The
// screen owns loading; runLoadThread.ts owns opening and checking.
//
// Plain text only, always: a comment's text is put on the page as a React text
// node and nothing else -- never as markup, never as a link, never as an image
// source (docs/DESIGN.md, "Comments (#44)"). The line breaks the author typed
// are kept by CSS (whitespace-pre-wrap), not by interpreting the text.
//
// Replies are indented by depth, capped so a deep thread does not run off the
// page; the path is what orders and nests them, not the indent.

import { Link } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { commentAuthorLabel, commentNotes, commentTimeLabel } from './threadNotes'
import type { CommentView } from './runLoadThread'

/** Indent steps drawn; deeper replies share the last one. */
const MAX_INDENT = 4

export function ThreadPanel({
  groupId,
  postTitle,
  comments,
  loading,
  error,
  hasMore,
  onLoadMore,
  onRetry,
}: {
  readonly groupId: string
  /** The post's title when the list passed it along; a thread opened cold has none. */
  readonly postTitle?: string | undefined
  readonly comments: readonly CommentView[]
  readonly loading: boolean
  readonly error: string | null
  readonly hasMore: boolean
  readonly onLoadMore: () => void
  /** Set when a page failed in a way another try can fix. */
  readonly onRetry?: (() => void) | undefined
}) {
  const empty = comments.length === 0 && !loading && error === null
  return (
    <div className="flex w-full max-w-xl flex-col gap-4 text-left">
      {postTitle !== undefined && postTitle !== '' && (
        <p className="break-words text-sm text-muted-foreground">On: {postTitle}</p>
      )}
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {empty && !hasMore && <p className="text-sm text-muted-foreground">No comments yet.</p>}
      {empty && hasMore && (
        <p className="text-sm text-muted-foreground">
          No comments to show here yet. More may follow.
        </p>
      )}
      {comments.map((comment) => (
        <article
          key={comment.path}
          data-depth={comment.depth}
          style={{
            marginLeft: `${String(Math.min(Math.max(comment.depth - 1, 0), MAX_INDENT))}rem`,
          }}
          className="flex flex-col gap-1.5 rounded-md border px-3 py-2"
        >
          <p className="text-xs text-muted-foreground">
            {commentAuthorLabel(comment)} · {commentTimeLabel(comment)}
          </p>
          {comment.content.kind === 'opened' && (
            <p className="whitespace-pre-wrap break-words text-sm">{comment.content.text}</p>
          )}
          {commentNotes(comment).map((note) => (
            <p
              key={note.text}
              className={`text-xs ${note.tone === 'warn' ? 'text-destructive' : 'text-muted-foreground'}`}
            >
              {note.text}
            </p>
          ))}
        </article>
      ))}
      {onRetry !== undefined && !loading && (
        <Button type="button" variant="outline" onClick={onRetry}>
          Try again
        </Button>
      )}
      {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
      {hasMore && !loading && onRetry === undefined && (
        <Button type="button" variant="outline" onClick={onLoadMore}>
          Load more comments
        </Button>
      )}
      <Link
        to={`/groups/${groupId}/posts`}
        className="text-sm text-primary underline-offset-4 hover:underline"
      >
        Back to posts
      </Link>
    </div>
  )
}
