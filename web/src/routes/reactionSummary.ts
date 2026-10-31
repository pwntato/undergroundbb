// What a row of reaction buttons shows for one target (the post, or one comment)
// -- #46. Pure, so the counts and the labels are tested without a DOM.
//
// Every reaction in the table gets a button, in table order, whether or not
// anyone used it, so the row does not jump about as reactions arrive. A
// reaction that did not open (a byte this build has no reaction for, or a
// failed decrypt) is counted apart, never as one of the seven and never dropped
// silently.

import { REACTIONS } from '@/lib/crypto/reaction'
import type { ReactionView } from './runLoadThread'

export interface ReactionButton {
  readonly index: number
  readonly emoji: string
  readonly label: string
  readonly count: number
  /** This reader's own reaction on the target is this one. */
  readonly mine: boolean
}

export interface ReactionSummary {
  readonly buttons: readonly ReactionButton[]
  /** Reactions on the target that could not be read. */
  readonly unreadable: number
  /** The table index of this reader's own reaction, or null (also when it is unreadable). */
  readonly mine: number | null
}

export function summarizeReactions(
  reactions: readonly ReactionView[],
  target: string,
  selfUserId: string,
): ReactionSummary {
  const counts = new Map<number, number>()
  let unreadable = 0
  let mine: number | null = null
  const seen = new Set<string>()
  for (const x of reactions) {
    // One per reactor: a repeat is the server misbehaving, and counts once.
    if (x.target !== target || seen.has(x.reactorUserId)) continue
    seen.add(x.reactorUserId)
    if (x.index === null) {
      unreadable += 1
      continue
    }
    counts.set(x.index, (counts.get(x.index) ?? 0) + 1)
    if (x.reactorUserId === selfUserId) mine = x.index
  }
  return {
    buttons: REACTIONS.map((r) => ({
      index: r.index,
      emoji: r.emoji,
      label: r.label,
      count: counts.get(r.index) ?? 0,
      mine: mine === r.index,
    })),
    unreadable,
    mine,
  }
}

/** The spoken name of a button: "Thumbs up, 3 reactions, yours". */
export function reactionButtonLabel(b: ReactionButton): string {
  const n = b.count === 1 ? '1 reaction' : `${String(b.count)} reactions`
  return `${b.label}, ${n}${b.mine ? ', yours' : ''}`
}

export function unreadableReactionsNote(n: number): string | null {
  if (n <= 0) return null
  return n === 1 ? '1 reaction could not be read.' : `${String(n)} reactions could not be read.`
}
