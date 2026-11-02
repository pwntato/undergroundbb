// Finding the item an open edit or delete form hangs on -- #328. After the password
// step a restored form can hang on a post or comment that is not on the first page
// (after "Load older posts", or a comment past the first 50). The screen then loads on,
// one page at a time, until the item shows; if the list ends without it the item is gone
// and the form closes. Both screens ask this one function what to do, so the rule is
// tested without a DOM.

export type FormSeek =
  /** Nothing to do: no form, the item is on screen, or the screen is busy or failed. */
  | { readonly kind: 'none' }
  /** Load the page behind this cursor. */
  | { readonly kind: 'loadMore'; readonly cursor: string }
  /** Every page is loaded and the item is not there. */
  | { readonly kind: 'gone' }

export function seekForm(input: {
  /** The id the open form hangs on (a post's sort key, a comment's path), if a form is open. */
  readonly formKey: string | undefined
  /** The first page has arrived, and no page is loading or failed. */
  readonly settled: boolean
  /** The ids on screen. */
  readonly shown: readonly string[]
  /** The cursor behind the last page, or undefined when it was the last. */
  readonly cursor: string | undefined
  /** The cursor this was last asked to load, so one page is never asked for twice in a row. */
  readonly lastAsked: string | undefined
}): FormSeek {
  if (input.formKey === undefined || !input.settled) return { kind: 'none' }
  if (input.shown.includes(input.formKey)) return { kind: 'none' }
  if (input.cursor === undefined) return { kind: 'gone' }
  if (input.cursor === input.lastAsked) return { kind: 'none' }
  return { kind: 'loadMore', cursor: input.cursor }
}
