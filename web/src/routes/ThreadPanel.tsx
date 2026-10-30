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
import { ReplyBox } from './ReplyBox'
import { attachesBeside } from './runCreateComment'
import { commentAuthorLabel, commentNotes, commentTimeLabel } from './threadNotes'
import type { CommentView } from './runLoadThread'

/** Indent steps drawn; deeper replies share the last one. */
const MAX_INDENT = 4

/** Everything the reply box needs from the screen; absent where replying makes no sense. */
export interface ThreadReply {
  /** The path being replied to, or null for a new top-level comment. */
  readonly replyTo: string | null
  readonly draft: string
  readonly maxBytes: number
  readonly sending: boolean
  readonly error: string | null
  readonly notice: string | null
  readonly onOpen: (replyTo: string | null) => void
  readonly onEdit: (draft: string) => void
  readonly onSend: () => void
}

export function ThreadPanel({
  groupId,
  postTitle,
  comments,
  loading,
  error,
  hasMore,
  onLoadMore,
  onRetry,
  reply,
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
  readonly reply?: ThreadReply | undefined
}) {
  // A box left pointing at a comment that is not on the page falls back to the bottom one.
  const inlineAt =
    reply?.replyTo !== null && reply?.replyTo !== undefined
      ? comments.find((c) => c.path === reply.replyTo)?.path
      : undefined
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
        <div key={comment.path} className="flex flex-col gap-2">
          <article
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
          {reply !== undefined && comment.depth > 0 && (
            <div
              style={{
                marginLeft: `${String(Math.min(Math.max(comment.depth - 1, 0), MAX_INDENT))}rem`,
              }}
            >
              {inlineAt === comment.path ? (
                <ReplyBox
                  id={`reply-${comment.path}`}
                  label="Your reply"
                  hint={
                    attachesBeside(comment.path)
                      ? 'Replies stop at this depth, so yours will appear beside this comment.'
                      : undefined
                  }
                  value={reply.draft}
                  maxBytes={reply.maxBytes}
                  sending={reply.sending}
                  error={reply.error}
                  autoFocus
                  onChange={reply.onEdit}
                  onSubmit={reply.onSend}
                  onCancel={() => {
                    reply.onOpen(null)
                  }}
                />
              ) : (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  disabled={reply.sending}
                  onClick={() => {
                    reply.onOpen(comment.path)
                  }}
                >
                  Reply
                </Button>
              )}
            </div>
          )}
        </div>
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
      {reply !== undefined && inlineAt === undefined && (
        <>
          {reply.notice !== null && (
            <Alert>
              <AlertDescription>{reply.notice}</AlertDescription>
            </Alert>
          )}
          <ReplyBox
            id="reply-top"
            label={comments.length === 0 ? 'Write the first comment' : 'Add a comment'}
            value={reply.draft}
            maxBytes={reply.maxBytes}
            sending={reply.sending}
            error={reply.error}
            onChange={reply.onEdit}
            onSubmit={reply.onSend}
          />
        </>
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
