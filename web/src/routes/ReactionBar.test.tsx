import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { REACTIONS } from '@/lib/crypto/reaction'
import { ReactionBar } from './ReactionBar'
import { elementsOf } from './elementTree.testkit'
import { summarizeReactions } from './reactionSummary'
import type { ReactionView } from './runLoadThread'

const rx = (target: string, reactorUserId: string, index: number | null): ReactionView => ({
  target,
  reactorUserId,
  index,
})

function render(
  reactions: readonly ReactionView[],
  over: { busy?: boolean; error?: string | null; target?: string } = {},
) {
  return renderToStaticMarkup(
    createElement(ReactionBar, {
      label: 'Reactions to this comment',
      summary: summarizeReactions(reactions, over.target ?? '0001', 'me'),
      busy: over.busy ?? false,
      error: over.error ?? null,
      onPress: () => {},
    }),
  )
}

const buttons = (html: string) => html.match(/<button[^>]*>/g) ?? []
// The class names hold `disabled:` variants, so look for the attribute itself.
const isDisabled = (tag: string) => / disabled=""/.test(tag)

describe('ReactionBar', () => {
  it('has a button for every reaction in the table, in order, in a labelled group', () => {
    const html = render([])
    expect(html).toContain('role="group"')
    expect(html).toContain('aria-label="Reactions to this comment"')
    const found = buttons(html).map((b) => Number(/data-reaction="(\d+)"/.exec(b)?.[1]))
    expect(found).toEqual(REACTIONS.map((r) => r.index))
    for (const r of REACTIONS) expect(html).toContain(r.emoji)
  })

  it('shows a count only where there is one, and speaks every count', () => {
    const html = render([rx('0001', 'a', 1), rx('0001', 'b', 1), rx('0001', 'c', 3)])
    expect(html).toContain('aria-label="Thumbs up, 2 reactions"')
    expect(html).toContain('aria-label="Laughing, 1 reaction"')
    expect(html).toContain('aria-label="Heart, 0 reactions"')
    expect(html).toContain('<span aria-hidden="true">2</span>')
    expect(html).not.toContain('<span aria-hidden="true">0</span>')
  })

  it("presses only the reader's own reaction, and says so", () => {
    const html = render([rx('0001', 'me', 5), rx('0001', 'you', 1)])
    const pressed = buttons(html).filter((b) => b.includes('aria-pressed="true"'))
    expect(pressed).toHaveLength(1)
    expect(pressed[0]).toContain('data-reaction="5"')
    expect(pressed[0]).toContain('Sad, 1 reaction, yours')
    expect(html.match(/aria-pressed="false"/g)).toHaveLength(REACTIONS.length - 1)
  })

  it('disables every button while the target is being saved, and none otherwise', () => {
    expect(buttons(render([], { busy: true })).every(isDisabled)).toBe(true)
    expect(buttons(render([])).some(isDisabled)).toBe(false)
  })

  it('says how many reactions could not be read, and nothing when all can', () => {
    expect(render([rx('0001', 'a', null), rx('0001', 'b', null)])).toContain(
      '2 reactions could not be read.',
    )
    expect(render([rx('0001', 'a', 1)])).not.toContain('could not be read')
  })

  it('shows why a press failed', () => {
    const html = render([], { error: 'Could not save your reaction. Try again.' })
    expect(html).toContain('Could not save your reaction. Try again.')
    expect(html).toContain('role="alert"')
    expect(render([])).not.toContain('role="alert"')
  })

  it('puts a reaction on another target nowhere', () => {
    const html = render([rx('0002', 'me', 1), rx('0000', 'you', 2)])
    expect(html).not.toContain('<span aria-hidden="true">1</span>')
  })
})

describe('ReactionBar presses', () => {
  it('reports the table index of the button pressed, and no other', () => {
    const pressed: number[] = []
    const tree = ReactionBar({
      label: 'x',
      summary: summarizeReactions([], '0001', 'me'),
      busy: false,
      error: null,
      onPress: (i) => pressed.push(i),
    })
    const buttons = elementsOf(tree).filter((e) => 'data-reaction' in e.props)
    expect(buttons).toHaveLength(REACTIONS.length)
    for (const b of buttons) (b.props['onClick'] as () => void)()
    expect(pressed).toEqual(REACTIONS.map((r) => r.index))
  })
})
