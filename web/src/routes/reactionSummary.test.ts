import { describe, expect, it } from 'vitest'
import { REACTIONS } from '@/lib/crypto/reaction'
import { reactionButtonLabel, summarizeReactions, unreadableReactionsNote } from './reactionSummary'
import type { ReactionView } from './runLoadThread'

const rx = (target: string, reactorUserId: string, index: number | null): ReactionView => ({
  target,
  reactorUserId,
  index,
})

describe('summarizeReactions', () => {
  it('has a button for every reaction in the table, in table order, even when unused', () => {
    const s = summarizeReactions([], '0001', 'me')
    expect(s.buttons.map((b) => b.index)).toEqual(REACTIONS.map((r) => r.index))
    expect(s.buttons.every((b) => b.count === 0 && !b.mine)).toBe(true)
    expect([s.mine, s.unreadable]).toEqual([null, 0])
  })

  it('counts each reaction on the target and no other target', () => {
    const s = summarizeReactions(
      [
        rx('0001', 'a', 1),
        rx('0001', 'b', 1),
        rx('0001', 'c', 3),
        rx('0002', 'd', 1),
        rx('0000', 'e', 1),
      ],
      '0001',
      'me',
    )
    expect(s.buttons.map((b) => b.count)).toEqual([2, 0, 1, 0, 0, 0, 0])
  })

  it("marks the reader's own reaction and nobody else's", () => {
    const s = summarizeReactions(
      [rx('0001', 'a', 2), rx('0001', 'me', 5), rx('0002', 'me', 1)],
      '0001',
      'me',
    )
    expect(s.mine).toBe(5)
    expect(s.buttons.filter((b) => b.mine).map((b) => b.index)).toEqual([5])
  })

  it("counts a reaction that could not be read apart, and does not call it the reader's", () => {
    const s = summarizeReactions(
      [rx('0001', 'a', null), rx('0001', 'me', null), rx('0001', 'b', 4)],
      '0001',
      'me',
    )
    expect(s.unreadable).toBe(2)
    expect(s.mine).toBeNull()
    expect(s.buttons.map((b) => b.count)).toEqual([0, 0, 0, 1, 0, 0, 0])
  })

  it('counts a repeated reactor once, the first', () => {
    const s = summarizeReactions(
      [rx('0001', 'a', 1), rx('0001', 'a', 2), rx('0001', 'a', null)],
      '0001',
      'me',
    )
    expect(s.buttons.map((b) => b.count)).toEqual([1, 0, 0, 0, 0, 0, 0])
    expect(s.unreadable).toBe(0)
  })

  it("reads the post's own target like any other", () => {
    const s = summarizeReactions([rx('0000', 'me', 7), rx('0001', 'me', 1)], '0000', 'me')
    expect([s.mine, s.buttons[6]!.count, s.buttons[0]!.count]).toEqual([7, 1, 0])
  })
})

describe('reaction labels', () => {
  const b = (count: number, mine: boolean) => ({
    index: 1,
    emoji: 'x',
    label: 'Thumbs up',
    count,
    mine,
  })
  it("speaks the name, the count and whether it is the reader's", () => {
    expect(reactionButtonLabel(b(0, false))).toBe('Thumbs up, 0 reactions')
    expect(reactionButtonLabel(b(1, false))).toBe('Thumbs up, 1 reaction')
    expect(reactionButtonLabel(b(3, true))).toBe('Thumbs up, 3 reactions, yours')
  })

  it('says how many could not be read, and nothing when none', () => {
    expect(unreadableReactionsNote(0)).toBeNull()
    expect(unreadableReactionsNote(1)).toBe('1 reaction could not be read.')
    expect(unreadableReactionsNote(4)).toBe('4 reactions could not be read.')
  })
})
