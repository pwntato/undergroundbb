// The two screens hold one piece of state (the current theme id) and hand the views an onSelect and,
// for the signup step, an onDone. There is no DOM here, so useState is stubbed: the screens are called
// as plain functions, and the real handlers they pass down are pressed against a stand-in page.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { THEME_ID_ATTRIBUTE, THEME_STORAGE_KEY } from '@/theme/applyTheme'
import type { AppearanceState } from './appearanceState'

const setState = vi.fn()
vi.mock('react', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react')>()
  return {
    ...actual,
    useState: (init: unknown) => [
      typeof init === 'function' ? (init as () => unknown)() : init,
      setState,
    ],
  }
})

const { AppearanceScreen } = await import('./AppearanceScreen')
const { ThemePickerStep } = await import('./ThemePickerStep')

interface Page {
  attrs: Map<string, string>
  stored: Map<string, string>
}

function standInPage(initialId: string | null): Page {
  const attrs = new Map<string, string>()
  if (initialId !== null) attrs.set(THEME_ID_ATTRIBUTE, initialId)
  const stored = new Map<string, string>()
  vi.stubGlobal('document', {
    documentElement: {
      style: { setProperty: () => undefined },
      setAttribute: (n: string, v: string) => void attrs.set(n, v),
      getAttribute: (n: string) => attrs.get(n) ?? null,
    },
  })
  vi.stubGlobal('window', {
    localStorage: {
      getItem: (k: string) => stored.get(k) ?? null,
      setItem: (k: string, v: string) => void stored.set(k, v),
    },
  })
  return { attrs, stored }
}

beforeEach(() => setState.mockClear())
afterEach(() => vi.unstubAllGlobals())

type Props = { currentId: string; onSelect: (id: string) => void; onDone?: () => void }
const propsOf = (el: unknown): Props => (el as { props: Props }).props

type AppearanceProps = {
  state: AppearanceState
  onSelect: (id: string) => void
}
const appearanceProps = (el: unknown): AppearanceProps => (el as { props: AppearanceProps }).props
/** The state the screen set through its updater, given the state it held. */
const nextState = (before: AppearanceState): AppearanceState => {
  const updater = setState.mock.calls[0]?.[0] as (s: AppearanceState) => AppearanceState
  return updater(before)
}

describe('AppearanceScreen wiring', () => {
  it('starts from the theme on the page, not from storage', () => {
    standInPage('zine')
    expect(appearanceProps(AppearanceScreen()).state.currentId).toBe('zine')
  })

  it('a card press switches the page, saves it, and updates the current id', () => {
    const page = standInPage(null)
    const props = appearanceProps(AppearanceScreen())
    expect(props.state.currentId).toBe('refined-terminal')
    props.onSelect('zine')
    expect(nextState(props.state).currentId).toBe('zine')
    expect(page.attrs.get('data-theme')).toBe('light')
    expect(page.attrs.get(THEME_ID_ATTRIBUTE)).toBe('zine')
    expect(page.stored.get(THEME_STORAGE_KEY)).toBe('zine')
  })

  it('an unknown id changes nothing and keeps the current id', () => {
    const page = standInPage('bbs-revival')
    const props = appearanceProps(AppearanceScreen())
    props.onSelect('nope')
    expect(nextState(props.state).currentId).toBe('bbs-revival')
    expect(page.stored.size).toBe(0)
  })

  it('the import, remove and export handlers it hands down run the real actions', () => {
    const page = standInPage(null)
    const props = appearanceProps(AppearanceScreen()) as AppearanceProps & {
      onImportText: (t: string) => void
      onImport: () => void
      onRemove: (id: string) => void
      onExport: () => void
    }
    const apply = (call: number, before: AppearanceState) => {
      const updater = setState.mock.calls[call]?.[0] as (s: AppearanceState) => AppearanceState
      return updater(before)
    }
    props.onImportText('{"name":"Mine","mode":"dark","tokens":{}}')
    const typed = apply(0, props.state)
    expect(typed.importText).toContain('Mine')
    props.onImport()
    const imported = apply(1, typed)
    expect(imported.customs.map((t) => t.name)).toEqual(['Mine'])
    expect(page.attrs.get(THEME_ID_ATTRIBUTE)).toBe(imported.currentId)
    props.onExport()
    expect(apply(2, imported).exportText).toContain('"name": "Mine"')
    props.onRemove(imported.currentId)
    expect(apply(3, imported).customs).toEqual([])
    expect(page.attrs.get(THEME_ID_ATTRIBUTE)).toBe('refined-terminal')
  })
})

describe('ThemePickerStep wiring', () => {
  it('a card press switches the page, saves it, and updates the current id', () => {
    const page = standInPage(null)
    propsOf(ThemePickerStep({ onDone: () => undefined })).onSelect('bbs-revival')
    expect(page.attrs.get(THEME_ID_ATTRIBUTE)).toBe('bbs-revival')
    expect(page.stored.get(THEME_STORAGE_KEY)).toBe('bbs-revival')
    expect(setState).toHaveBeenCalledExactlyOnceWith('bbs-revival')
  })

  it("hands the caller's onDone to the Continue button, so the signup step can finish", () => {
    standInPage(null)
    const onDone = vi.fn()
    const props = propsOf(ThemePickerStep({ onDone }))
    expect(props.onDone).toBe(onDone)
    props.onDone?.()
    expect(onDone).toHaveBeenCalledOnce()
  })

  it('starts from the theme on the page', () => {
    standInPage('bbs-revival')
    expect(propsOf(ThemePickerStep({ onDone: () => undefined })).currentId).toBe('bbs-revival')
  })
})
