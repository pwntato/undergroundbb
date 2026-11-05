// The bottom reply box when no inline box is drawn -- #330. While a restored reply's target
// is still being sought (it may be on a later page), replyTo is kept, so a Send from the
// bottom box would seal under a comment the reader cannot see, under a label that said "new
// comment". So that box says what is happening and cannot send. It frees itself when the
// target shows (the inline box takes over), `endReached` drops the target (replyTo null), or
// the reader chooses "Make this a new comment" (the same drop).

export interface FallbackBox {
  readonly label: string
  readonly hint: string | undefined
  /** True when Send must stay off. */
  readonly waiting: boolean
}

export function fallbackBox(input: {
  readonly replyTo: string | null
  readonly commentCount: number
  /** A page failed to load, so nothing is loading and the seek has stopped. */
  readonly loadFailed: boolean
}): FallbackBox {
  if (input.replyTo !== null) {
    return input.loadFailed
      ? {
          label: "Couldn't load the comment you are replying to",
          hint: 'Use Try again above to load it, then you can send this. Or make this a new comment.',
          waiting: true,
        }
      : {
          label: 'Reply to a comment that is still loading',
          hint: 'You can send this once the comment shows. If the thread ends without it, this becomes a new comment. Or make it a new comment now; you still press Send.',
          waiting: true,
        }
  }
  return {
    label: input.commentCount === 0 ? 'Write the first comment' : 'Add a comment',
    hint: undefined,
    waiting: false,
  }
}
