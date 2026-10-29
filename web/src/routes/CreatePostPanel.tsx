// The presentational half of CreatePostScreen -- #42. Prop-driven, so it can be
// tested with renderToStaticMarkup (see GroupList.tsx's header). The screen
// owns loading, sealing and sending.
//
// Plain text only: a post is rendered as text and never as markup, so nothing
// a member writes can pull an image or a link-preview into another member's
// view. The counters count UTF-8 bytes, the unit the limits are in.

import { useState, type FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { utf8Length } from '@/lib/crypto/post'
import { FORM_PROBLEMS, validatePostForm, type PostLimits } from './runCreatePost'

export function CreatePostPanel({
  limits,
  posting,
  message,
  error,
  onSubmit,
}: {
  readonly limits: PostLimits
  readonly posting: boolean
  /** Shown after a successful post. */
  readonly message: string | null
  readonly error: string | null
  readonly onSubmit: (title: string, body: string) => void
}) {
  const [title, setTitle] = useState('')
  const [body, setBody] = useState('')
  const titleBytes = utf8Length(title)
  const bodyBytes = utf8Length(body)
  const problem = validatePostForm(title, body, limits)
  // An empty title is not an error to flag while typing; the button just waits.
  const shown = problem === 'titleEmpty' ? null : problem

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (problem === null && !posting) {
      onSubmit(title, body)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex w-full flex-col gap-4 text-left">
      {message !== null && (
        <Alert>
          <AlertDescription>{message}</AlertDescription>
        </Alert>
      )}
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="post-title">Title</Label>
        <Input
          id="post-title"
          value={title}
          onChange={(e) => {
            setTitle(e.target.value)
          }}
          aria-invalid={titleBytes > limits.maxTitleBytes}
          disabled={posting}
          autoComplete="off"
        />
        <p
          className={`text-xs ${titleBytes > limits.maxTitleBytes ? 'text-destructive' : 'text-muted-foreground'}`}
        >
          {titleBytes} / {limits.maxTitleBytes} bytes
        </p>
      </div>
      <div className="flex flex-col gap-1.5">
        <Label htmlFor="post-body">Post</Label>
        <textarea
          id="post-body"
          value={body}
          onChange={(e) => {
            setBody(e.target.value)
          }}
          aria-invalid={bodyBytes > limits.maxBodyBytes}
          disabled={posting}
          rows={8}
          className="w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-2 text-base shadow-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive md:text-sm dark:bg-input/30"
        />
        <p
          className={`text-xs ${bodyBytes > limits.maxBodyBytes ? 'text-destructive' : 'text-muted-foreground'}`}
        >
          {bodyBytes} / {limits.maxBodyBytes} bytes. Plain text only.
        </p>
      </div>
      {shown !== null && <p className="text-sm text-destructive">{FORM_PROBLEMS[shown]}</p>}
      <Button type="submit" disabled={posting || problem !== null}>
        {posting ? 'Posting…' : 'Post'}
      </Button>
    </form>
  )
}
