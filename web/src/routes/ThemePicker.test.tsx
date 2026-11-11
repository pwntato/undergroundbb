import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { BUILT_IN_THEMES } from '@/theme/themes'
import { ThemePicker } from './ThemePicker'
import { elementsOf } from './elementTree.testkit'

const cards = (el: ReturnType<typeof ThemePicker>) =>
  elementsOf(el).filter((n) => typeof n.props['data-theme-id'] === 'string')

describe('ThemePicker', () => {
  it('lists every built-in theme by name, in order, with a sample of each', () => {
    const out = renderToStaticMarkup(
      createElement(ThemePicker, { currentId: 'zine', onSelect: () => undefined }),
    )
    let at = -1
    for (const t of BUILT_IN_THEMES) {
      const i = out.indexOf(t.name)
      expect(i, t.name).toBeGreaterThan(at)
      at = i
    }
    expect(out.match(/Sample heading/g)).toHaveLength(BUILT_IN_THEMES.length)
    expect(out).not.toContain('Coming soon')
  })

  it('marks exactly the current theme as checked, in words as well as colour', () => {
    for (const current of BUILT_IN_THEMES) {
      const el = ThemePicker({ currentId: current.id, onSelect: () => undefined })
      const checked = cards(el).filter((n) => n.props['aria-pressed'] === true)
      expect(checked.map((n) => n.props['data-theme-id'])).toEqual([current.id])
    }
    const out = renderToStaticMarkup(
      createElement(ThemePicker, { currentId: 'bbs-revival', onSelect: () => undefined }),
    )
    expect(out.match(/>Selected</g)).toHaveLength(1)
  })

  it('calls onSelect with the id of the card pressed, through the real onClick', () => {
    for (const t of BUILT_IN_THEMES) {
      const onSelect = vi.fn()
      const el = ThemePicker({ currentId: 'nothing', onSelect })
      const card = cards(el).find((n) => n.props['data-theme-id'] === t.id)
      if (card === undefined) throw new Error('card not found')
      ;(card.props['onClick'] as () => void)()
      expect(onSelect).toHaveBeenCalledExactlyOnceWith(t.id)
    }
  })

  it('draws the sample with inline styles from the theme, and hides it from screen readers', () => {
    const el = ThemePicker({ currentId: 'zine', onSelect: () => undefined })
    const frames = elementsOf(el).filter((n) => n.props['aria-hidden'] === 'true')
    expect(frames).toHaveLength(BUILT_IN_THEMES.length)
    const zine = frames[BUILT_IN_THEMES.findIndex((t) => t.id === 'zine')]
    if (zine === undefined) throw new Error('zine sample not found')
    expect((zine.props['style'] as { background: string }).background).toBe(
      BUILT_IN_THEMES.find((t) => t.id === 'zine')?.tokens['background'],
    )
  })
})
