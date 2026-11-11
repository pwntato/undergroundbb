// The two screens hold one piece of state (the current theme id) and hand the views an onSelect and,
// for the signup step, an onDone. There is no DOM here, so useState is stubbed: the screens are called
// as plain functions, and the real handlers they pass down are pressed against a stand-in page.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { THEME_ID_ATTRIBUTE, THEME_STORAGE_KEY } from '@/theme/applyTheme'

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

describe('AppearanceScreen wiring', () => {
  it('starts from the theme on the page, not from storage', () => {
    standInPage('zine')
    expect(propsOf(AppearanceScreen()).currentId).toBe('zine')
  })

  it('a card press switches the page, saves it, and updates the current id', () => {
    const page = standInPage(null)
    const props = propsOf(AppearanceScreen())
    expect(props.currentId).toBe('refined-terminal')
    props.onSelect('zine')
    expect(page.attrs.get('data-theme')).toBe('light')
    expect(page.attrs.get(THEME_ID_ATTRIBUTE)).toBe('zine')
    expect(page.stored.get(THEME_STORAGE_KEY)).toBe('zine')
    expect(setState).toHaveBeenCalledExactlyOnceWith('zine')
  })

  it('an unknown id changes nothing and keeps the current id', () => {
    const page = standInPage('bbs-revival')
    propsOf(AppearanceScreen()).onSelect('nope')
    expect(page.stored.size).toBe(0)
    expect(setState).toHaveBeenCalledExactlyOnceWith('bbs-revival')
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
