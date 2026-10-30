// The reply box -- #44. Prop-driven, so it can be tested with
// renderToStaticMarkup (see CreatePostPanel.tsx's header). ThreadScreen owns the
// draft, sealing and sending.
//
// Plain text only, and the counter counts UTF-8 bytes, the unit the server's
// limit is in.

import type { FormEvent } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { utf8Length } from '@/lib/crypto/post'
import { COMMENT_PROBLEMS, validateComment } from './runCreateComment'

export function ReplyBox({
  id,
  label,
  hint,
  value,
  maxBytes,
  sending,
  error,
  autoFocus,
  onChange,
  onSubmit,
  onCancel,
}: {
  /** Unique on the page, for the label. */
  readonly id: string
  readonly label: string
  /** An extra line under the label, e.g. where the reply will appear. */
  readonly hint?: string | undefined
  readonly value: string
  readonly maxBytes: number
  readonly sending: boolean
  readonly error: string | null
  readonly autoFocus?: boolean
  readonly onChange: (value: string) => void
  readonly onSubmit: () => void
  /** Shown for an inline box; the bottom box has nothing to close. */
  readonly onCancel?: (() => void) | undefined
}) {
  const bytes = utf8Length(value)
  const problem = validateComment(value, maxBytes)
  // An empty box is not an error to flag while typing; the button just waits.
  const shown = problem === 'empty' ? null : problem

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    if (problem === null && !sending) onSubmit()
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-1.5">
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <label htmlFor={id} className="text-sm font-medium">
        {label}
      </label>
      {hint !== undefined && <p className="text-xs text-muted-foreground">{hint}</p>}
      <textarea
        id={id}
        value={value}
        onChange={(e) => {
          onChange(e.target.value)
        }}
        aria-invalid={bytes > maxBytes}
        disabled={sending}
        autoFocus={autoFocus === true}
        rows={4}
        className="w-full min-w-0 rounded-md border border-input bg-transparent px-3 py-2 text-base shadow-xs outline-none placeholder:text-muted-foreground focus-visible:border-ring focus-visible:ring-[3px] focus-visible:ring-ring/50 disabled:cursor-not-allowed disabled:opacity-50 aria-invalid:border-destructive md:text-sm dark:bg-input/30"
      />
      <p className={`text-xs ${bytes > maxBytes ? 'text-destructive' : 'text-muted-foreground'}`}>
        {bytes} / {maxBytes} bytes. Plain text only.
      </p>
      {shown !== null && <p className="text-sm text-destructive">{COMMENT_PROBLEMS[shown]}</p>}
      <div className="flex gap-2">
        <Button type="submit" disabled={sending || problem !== null}>
          {sending ? 'Sending…' : 'Send'}
        </Button>
        {onCancel !== undefined && (
          <Button type="button" variant="outline" disabled={sending} onClick={onCancel}>
            Cancel
          </Button>
        )}
      </div>
    </form>
  )
}
