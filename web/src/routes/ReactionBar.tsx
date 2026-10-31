// A row of reaction buttons for one target (the post, or one comment) -- #46.
// Prop-driven, so it can be tested with renderToStaticMarkup (see ReplyBox.tsx's
// header). ThreadScreen owns sealing and sending; reactionSummary.ts owns the
// counts and the spoken labels.
//
// Every reaction in the fixed table has a button, used or not, so the row keeps
// its shape as reactions arrive. Your own is pressed; pressing it takes it back,
// pressing another changes it. A target being saved is disabled, so a second press
// cannot race the first.

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import {
  reactionButtonLabel,
  unreadableReactionsNote,
  type ReactionSummary,
} from './reactionSummary'

export function ReactionBar({
  label,
  summary,
  busy,
  error,
  onPress,
}: {
  /** Names the group of buttons for a screen reader, e.g. "Reactions to this comment". */
  readonly label: string
  readonly summary: ReactionSummary
  readonly busy: boolean
  /** Why the last press on this target did not go through, or null. */
  readonly error: string | null
  readonly onPress: (index: number) => void
}) {
  const note = unreadableReactionsNote(summary.unreadable)
  return (
    <div className="flex flex-col gap-1">
      <div role="group" aria-label={label} className="flex flex-wrap items-center gap-1">
        {summary.buttons.map((b) => (
          <Button
            key={b.index}
            type="button"
            variant={b.mine ? 'secondary' : 'ghost'}
            size="xs"
            aria-pressed={b.mine}
            aria-label={reactionButtonLabel(b)}
            title={b.label}
            disabled={busy}
            data-reaction={b.index}
            onClick={() => {
              onPress(b.index)
            }}
          >
            <span aria-hidden="true">{b.emoji}</span>
            {b.count > 0 && <span aria-hidden="true">{b.count}</span>}
          </Button>
        ))}
      </div>
      {note !== null && <p className="text-xs text-muted-foreground">{note}</p>}
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
    </div>
  )
}
