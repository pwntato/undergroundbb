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
import type { ControlMode } from './commentControls'
import { COPY_ADVISORY } from './editCopy'
import { ReactionBar } from './ReactionBar'
import { summarizeReactions } from './reactionSummary'
import { ReplyBox } from './ReplyBox'
import { fallbackBox } from './replyFallbackBox'
import { attachesBeside } from './runCreateComment'
import { DELETED_POST_TEXT, editedMark } from './postNotes'
import { PostContent, PostControls, type PostListControls } from './GroupPostsPanel'
import {
  commentAuthorLabel,
  commentNotes,
  commentTimeLabel,
  DELETED_COMMENT_TEXT,
} from './threadNotes'
import { isDeletedPost, type PostEntry } from './runListPosts'
import {
  isDeletedComment,
  POST_TARGET,
  type CommentView,
  type ReactionView,
  type ThreadEntry,
} from './runLoadThread'

/** The post the thread hangs on, with its Edit and Delete (#318). */
export interface ThreadPost {
  readonly entry: PostEntry
  readonly controls: PostListControls
}

/** The post as the top of the thread: its text and who wrote it, or that it was deleted. */
export function ThreadPostSection({ post }: { readonly post: ThreadPost }) {
  const { entry, controls } = post
  if (isDeletedPost(entry)) {
    return (
      <article className="rounded-md border px-3 py-2">
        <p className="text-sm italic text-muted-foreground">{DELETED_POST_TEXT}</p>
      </article>
    )
  }
  return (
    <article className="flex flex-col gap-1.5 rounded-md border px-3 py-2">
      <PostContent post={entry} />
      {controls.mode.kind === 'idle' && controls.error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{controls.error}</AlertDescription>
        </Alert>
      )}
      <PostControls post={entry} controls={controls} />
    </article>
  )
}

/** Indent steps drawn; deeper replies share the last one. */
const MAX_INDENT = 4

function indent(depth: number): string {
  return `${String(Math.min(Math.max(depth - 1, 0), MAX_INDENT))}rem`
}

/** The "edited" marker after a byline (#45); the exact time is in the tooltip. */
function EditedMark({
  content,
}: {
  readonly content: { readonly editedAt?: string; readonly timeSuspect: boolean }
}) {
  const mark = editedMark(content)
  if (mark === null) return null
  return (
    <>
      {' · '}
      <span title={mark.title}>{mark.text}</span>
    </>
  )
}

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

/** The advisory under an edit or a delete: deletion and editing cannot recall what was read. */
export { COPY_ADVISORY }

/** The question asked before a delete. */
export const DELETE_QUESTION = 'Delete this comment? Replies stay.'

/** What Edit and Delete on a comment need from the screen. */
export interface ThreadControls {
  /** The reader, whose own comments get Edit and Delete. */
  readonly selfUserId: string
  /** An admin may delete anyone's comment. */
  readonly isAdmin: boolean
  /** The post is gone for writing: Edit is hidden, Delete stays. */
  readonly readOnly: boolean
  readonly mode: ControlMode
  readonly busy: boolean
  readonly error: string | null
  readonly maxBytes: number
  readonly onEditOpen: (path: string, text: string) => void
  readonly onDraft: (draft: string) => void
  readonly onSave: () => void
  readonly onDeleteAsk: (path: string) => void
  readonly onDeleteConfirm: () => void
  readonly onClose: () => void
}

/** What the reaction buttons need from the screen; absent where reacting makes no sense. */
export interface ThreadReactions {
  readonly reactions: readonly ReactionView[]
  /** The reader, whose own reaction on each target is pressed. */
  readonly selfUserId: string
  /** Targets whose reaction is being saved or taken back. */
  readonly reacting: readonly string[]
  readonly error: { readonly target: string; readonly message: string } | null
  /** Said once for the whole page, e.g. the comment reacted to is gone. */
  readonly notice: string | null
  /** The post is gone for writing: the buttons stay, with their counts, but cannot be pressed. */
  readonly readOnly: boolean
  /** False until the first page is in: the post's own reactions come with it. */
  readonly ready: boolean
  /** A press of reaction button `index` on `target`; whether it sets or takes back is decided from what is shown. */
  readonly onPress: (target: string, index: number) => void
}

/** Edit and Delete for one comment, or the form either of them opened (#45). */
export function CommentControls({
  comment,
  controls,
}: {
  readonly comment: CommentView
  readonly controls: ThreadControls
}) {
  const mine = comment.authorUserId === controls.selfUserId
  // An unreadable comment has no text to start from and no original time to keep.
  const opened = comment.content.kind === 'opened' ? comment.content : null
  const canEdit = mine && !controls.readOnly && opened !== null
  const canDelete = mine || controls.isAdmin
  if (!canEdit && !canDelete) return null
  const { mode, busy, error } = controls
  const style = { marginLeft: indent(comment.depth) }
  if (mode.kind === 'editing' && mode.path === comment.path) {
    return (
      <div style={style}>
        <ReplyBox
          id={`edit-${comment.path}`}
          label="Edit your comment"
          hint={COPY_ADVISORY}
          value={mode.draft}
          maxBytes={controls.maxBytes}
          sending={busy}
          error={error}
          autoFocus
          submitLabel="Save"
          unchanged={mode.draft === mode.original}
          onChange={controls.onDraft}
          onSubmit={controls.onSave}
          onCancel={controls.onClose}
        />
      </div>
    )
  }
  if (mode.kind === 'confirmDelete' && mode.path === comment.path) {
    return (
      <div style={style} className="flex flex-col gap-1.5">
        {error !== null && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <p className="text-sm font-medium">{DELETE_QUESTION}</p>
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
    <div style={style} className="flex gap-1">
      {canEdit && (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={busy}
          onClick={() => {
            controls.onEditOpen(comment.path, opened.text)
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
            controls.onDeleteAsk(comment.path)
          }}
        >
          Delete
        </Button>
      )}
    </div>
  )
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
  reactions,
  controls,
  post,
  postProblem,
}: {
  readonly groupId: string
  /** The post's title when the list passed it along; a thread opened cold has none. */
  readonly postTitle?: string | undefined
  readonly comments: readonly ThreadEntry[]
  readonly loading: boolean
  readonly error: string | null
  readonly hasMore: boolean
  readonly onLoadMore: () => void
  /** Set when a page failed in a way another try can fix. */
  readonly onRetry?: (() => void) | undefined
  readonly reply?: ThreadReply | undefined
  readonly reactions?: ThreadReactions | undefined
  readonly controls?: ThreadControls | undefined
  /** The post itself once it is loaded (#318); until then the title the list passed along. */
  readonly post?: ThreadPost | undefined
  /** Why the post could not be shown, when it could not. */
  readonly postProblem?: string | null | undefined
}) {
  const barFor = (target: string, label: string) => {
    if (reactions === undefined) return null
    const summary = summarizeReactions(reactions.reactions, target, reactions.selfUserId)
    return (
      <ReactionBar
        label={label}
        summary={summary}
        busy={reactions.readOnly || reactions.reacting.includes(target)}
        error={reactions.error?.target === target ? reactions.error.message : null}
        onPress={(index) => {
          reactions.onPress(target, index)
        }}
      />
    )
  }
  // A box left pointing at a comment that is not on the page falls back to the bottom one.
  const inlineAt =
    reply?.replyTo !== null && reply?.replyTo !== undefined
      ? comments.find((c) => c.path === reply.replyTo)?.path
      : undefined
  const bottom = fallbackBox({ replyTo: reply?.replyTo ?? null, commentCount: comments.length })
  const empty = comments.length === 0 && !loading && error === null
  return (
    <div className="flex w-full max-w-xl flex-col gap-4 text-left">
      {post !== undefined ? (
        <ThreadPostSection post={post} />
      ) : (
        postTitle !== undefined &&
        postTitle !== '' && (
          <p className="break-words text-sm text-muted-foreground">On: {postTitle}</p>
        )
      )}
      {postProblem != null && (
        <Alert variant="destructive">
          <AlertDescription>{postProblem}</AlertDescription>
        </Alert>
      )}
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
      {reactions?.notice != null && (
        <Alert>
          <AlertDescription>{reactions.notice}</AlertDescription>
        </Alert>
      )}
      {reactions?.ready === true && barFor(POST_TARGET, 'Reactions to the post')}
      {empty && !hasMore && <p className="text-sm text-muted-foreground">No comments yet.</p>}
      {empty && hasMore && (
        <p className="text-sm text-muted-foreground">
          No comments to show here yet. More may follow.
        </p>
      )}
      {comments.map((comment) =>
        isDeletedComment(comment) ? (
          // No author, time, reactions or reply: nothing of it is served but its place.
          <article
            key={comment.path}
            data-depth={comment.depth}
            style={{ marginLeft: indent(comment.depth) }}
            className="rounded-md border px-3 py-2"
          >
            <p className="text-sm italic text-muted-foreground">{DELETED_COMMENT_TEXT}</p>
          </article>
        ) : (
          <div key={comment.path} className="flex flex-col gap-2">
            <article
              data-depth={comment.depth}
              style={{ marginLeft: indent(comment.depth) }}
              className="flex flex-col gap-1.5 rounded-md border px-3 py-2"
            >
              <p className="text-xs text-muted-foreground">
                {commentAuthorLabel(comment)} · {commentTimeLabel(comment)}
                {comment.content.kind === 'opened' && <EditedMark content={comment.content} />}
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
              {comment.depth > 0 && barFor(comment.path, 'Reactions to this comment')}
            </article>
            {controls !== undefined && <CommentControls comment={comment} controls={controls} />}
            {reply !== undefined && comment.depth > 0 && (
              <div style={{ marginLeft: indent(comment.depth) }}>
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
        ),
      )}
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
            label={bottom.label}
            hint={bottom.hint}
            unchanged={bottom.waiting}
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
