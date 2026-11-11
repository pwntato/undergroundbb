import { describe, expect, it } from 'vitest'
import { MAX_CUSTOM_THEMES, validateCustomTheme, type CustomTheme } from './customTheme'
import {
  CUSTOM_THEMES_KEY,
  addCustomTheme,
  loadCustomThemes,
  removeCustomTheme,
  type CustomThemeStore,
} from './customThemes'

function memoryStore(initial: Record<string, string> = {}) {
  const data = new Map(Object.entries(initial))
  const store: CustomThemeStore = {
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
  }
  return { data, store }
}

function make(name: string, over: Record<string, string> = {}): CustomTheme {
  const r = validateCustomTheme(JSON.stringify({ name, mode: 'dark', tokens: over }))
  if (!r.ok) throw new Error(r.errors.join())
  return r.theme
}

describe('saving and loading', () => {
  it('keeps a theme and reads it back', () => {
    const { store } = memoryStore()
    const t = make('Mine', { primary: 'oklch(0.8 0.1 150)' })
    expect(addCustomTheme(t, store).ok).toBe(true)
    expect(loadCustomThemes(store)).toEqual([t])
  })

  it('the same name replaces the saved theme instead of adding a second', () => {
    const { store } = memoryStore()
    addCustomTheme(make('Mine', { primary: 'oklch(0.8 0.1 150)' }), store)
    addCustomTheme(make('Mine', { primary: 'oklch(0.8 0.1 200)' }), store)
    const themes = loadCustomThemes(store)
    expect(themes).toHaveLength(1)
    expect(themes[0]?.tokens['primary']).toBe('oklch(0.8 0.1 200)')
  })

  it('refuses a sixth different theme, but still lets one of the five be replaced', () => {
    const { store } = memoryStore()
    for (let i = 0; i < MAX_CUSTOM_THEMES; i++)
      expect(addCustomTheme(make(`T${i}`), store).ok).toBe(true)
    const sixth = addCustomTheme(make('Sixth'), store)
    expect(sixth.ok).toBe(false)
    expect(loadCustomThemes(store)).toHaveLength(MAX_CUSTOM_THEMES)
    expect(addCustomTheme(make('T0', { primary: 'oklch(0.8 0.1 90)' }), store).ok).toBe(true)
  })

  it('says so when the browser will not save, instead of pretending', () => {
    const throwing: CustomThemeStore = {
      getItem: () => null,
      setItem: () => {
        throw new Error('blocked')
      },
    }
    const r = addCustomTheme(make('Mine'), throwing)
    expect(r.ok).toBe(false)
    expect(addCustomTheme(make('Mine'), null).ok).toBe(false)
  })

  it('removes one theme and leaves the others', () => {
    const { store } = memoryStore()
    const a = make('A')
    const b = make('B')
    addCustomTheme(a, store)
    addCustomTheme(b, store)
    expect(removeCustomTheme(a.id, store)).toEqual([b])
    expect(loadCustomThemes(store)).toEqual([b])
  })
})

describe('what is read back is checked again', () => {
  const stored = (list: unknown) => memoryStore({ [CUSTOM_THEMES_KEY]: JSON.stringify(list) }).store
  const good = { name: 'Good', mode: 'dark', tokens: { primary: 'oklch(0.8 0.1 150)' } }

  it('drops an entry whose value was edited into something not allowed, keeps the rest', () => {
    const evil = { name: 'Evil', mode: 'dark', tokens: { primary: 'red; background: url(//x)' } }
    const themes = loadCustomThemes(stored([evil, good]))
    expect(themes.map((t) => t.name)).toEqual(['Good'])
  })

  it('drops an entry that is unreadable, has an unknown token, or is not an object', () => {
    const unreadable = { name: 'Dim', mode: 'dark', tokens: { foreground: 'oklch(0.2 0.01 255)' } }
    const unknown = { name: 'Pos', mode: 'dark', tokens: { position: 'fixed' } }
    expect(loadCustomThemes(stored([unreadable, unknown, 5, null, 'x', [good]]))).toEqual([])
  })

  it('reads only the first five, ignores duplicates, and survives bad storage', () => {
    const many = Array.from({ length: 9 }, (_, i) => ({ name: `T${i}`, mode: 'dark', tokens: {} }))
    expect(loadCustomThemes(stored(many))).toHaveLength(MAX_CUSTOM_THEMES)
    expect(loadCustomThemes(stored([good, good]))).toHaveLength(1)
    expect(loadCustomThemes(memoryStore({ [CUSTOM_THEMES_KEY]: '{not json' }).store)).toEqual([])
    expect(loadCustomThemes(memoryStore({ [CUSTOM_THEMES_KEY]: '{"a":1}' }).store)).toEqual([])
    expect(loadCustomThemes(null)).toEqual([])
    const throwing: CustomThemeStore = {
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: () => undefined,
    }
    expect(loadCustomThemes(throwing)).toEqual([])
  })
})
