import { describe, expect, it, vi } from 'vitest'
import { createElement } from 'react'
import { MemoryRouter } from 'react-router'
import { renderToStaticMarkup } from 'react-dom/server'
import { pickTheme, THEME_STORAGE_KEY, type ThemeStore, type ThemeTarget } from '@/theme/applyTheme'
import { AppearanceView } from './AppearanceScreen'
import { ThemePickerStepView } from './ThemePickerStep'
import { ThemePicker, type ThemePickerProps } from './ThemePicker'
import { elementsOf, type AnyElement } from './elementTree.testkit'

function press(el: { props: Record<string, unknown> } | undefined): void {
  if (el === undefined) throw new Error('element not found')
  ;(el.props['onClick'] as () => void)()
}

/** A page and a store to switch, and an onSelect wired the way the real screens wire it. */
function harness() {
  const attrs = new Map<string, string>()
  const target: ThemeTarget = {
    style: { setProperty: () => undefined },
    setAttribute: (n, v) => void attrs.set(n, v),
  }
  const data = new Map<string, string>()
  const store: ThemeStore = {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
  }
  const current = { id: 'refined-terminal' }
  const onSelect = (id: string) => {
    current.id = pickTheme(id, current.id, target, store)
  }
  return { attrs, data, current, onSelect }
}

/** The card for a theme: the view returns a <ThemePicker>, so render that one level, as a function. */
function card(view: ReturnType<typeof ThemePickerStepView>, id: string): AnyElement | undefined {
  const picker = elementsOf(view).find((n) => n.type === ThemePicker)
  if (picker === undefined) throw new Error('no ThemePicker in the view')
  return elementsOf(ThemePicker(picker.props as unknown as ThemePickerProps)).find(
    (n) => n.props['data-theme-id'] === id,
  )
}
const continueButton = (el: ReturnType<typeof ThemePickerStepView>) =>
  elementsOf(el).find(
    (n) => (n.type as { name?: string }).name === 'Button' && n.props['onClick'] !== undefined,
  )

const blankState = {
  currentId: 'refined-terminal',
  customs: [],
  invalid: [],
  notice: null,
  importText: '',
  errors: [],
  exportText: null,
}
const noop = {
  onSelect: () => undefined,
  onImportText: () => undefined,
  onImport: () => undefined,
  onRemove: () => undefined,
  onDiscard: () => undefined,
  onExport: () => undefined,
}

describe('ThemePickerStepView (the signup finish step)', () => {
  it('moves on when Continue is pressed, through its real onClick', () => {
    const onDone = vi.fn()
    const el = ThemePickerStepView({ currentId: 'zine', onSelect: () => undefined, onDone })
    press(continueButton(el))
    expect(onDone).toHaveBeenCalledOnce()
  })

  it('does not move on just because a card is pressed, and Continue does not select anything', () => {
    const onDone = vi.fn()
    const onSelect = vi.fn()
    const el = ThemePickerStepView({ currentId: 'zine', onSelect, onDone })
    press(card(el, 'bbs-revival'))
    expect(onDone).not.toHaveBeenCalled()
    expect(onSelect).toHaveBeenCalledExactlyOnceWith('bbs-revival')
    press(continueButton(el))
    expect(onSelect).toHaveBeenCalledOnce()
  })

  it('pressing a card switches the page and the choice is what Continue leaves showing', () => {
    const h = harness()
    const el = ThemePickerStepView({
      currentId: h.current.id,
      onSelect: h.onSelect,
      onDone: () => undefined,
    })
    press(card(el, 'zine'))
    expect(h.attrs.get('data-theme')).toBe('light')
    expect(h.current.id).toBe('zine')
    expect(h.data.get(THEME_STORAGE_KEY)).toBe('zine')
  })

  it('offers no way to skip that differs from Continue, and no "Coming soon"', () => {
    const out = renderToStaticMarkup(
      createElement(ThemePickerStepView, {
        currentId: 'zine',
        onSelect: () => undefined,
        onDone: () => undefined,
      }),
    )
    expect(out).not.toContain('Coming soon')
    expect(out).toContain('Continue')
    expect(out).toContain('Pick a look')
  })
})

describe('AppearanceView', () => {
  it('shows the picker with the current theme marked and a way back', () => {
    const out = renderToStaticMarkup(
      createElement(
        MemoryRouter,
        null,
        createElement(AppearanceView, {
          ...noop,
          state: { ...blankState, currentId: 'bbs-revival' },
        }),
      ),
    )
    expect(out).toContain('Appearance')
    expect(out).toContain('href="/"')
    expect(out.match(/>Selected</g)).toHaveLength(1)
  })

  it('pressing a card switches the page and saves it', () => {
    const h = harness()
    const el = AppearanceView({
      ...noop,
      state: { ...blankState, currentId: h.current.id },
      onSelect: h.onSelect,
    })
    press(card(el, 'bbs-revival'))
    expect(h.attrs.get('data-theme')).toBe('dark')
    expect(h.attrs.get('data-theme-id')).toBe('bbs-revival')
    expect(h.current.id).toBe('bbs-revival')
    expect(h.data.get(THEME_STORAGE_KEY)).toBe('bbs-revival')
  })
})
