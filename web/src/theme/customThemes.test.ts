import { describe, expect, it } from 'vitest'
import { MAX_CUSTOM_THEMES, validateCustomTheme, type CustomTheme } from './customTheme'
import {
  CUSTOM_THEMES_KEY,
  addCustomTheme,
  discardInvalidTheme,
  loadCustomThemes,
  readSavedThemes,
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

describe('entries that no longer pass are kept, not erased', () => {
  const old = { name: 'Old', mode: 'dark', tokens: { 'border-width': '0' } }
  const seeded = () => memoryStore({ [CUSTOM_THEMES_KEY]: JSON.stringify([old]) })

  it('readSavedThemes reports the entry with its reasons and its JSON, and loadCustomThemes skips it', () => {
    const { store } = seeded()
    const saved = readSavedThemes(store)
    expect(saved.valid).toEqual([])
    expect(saved.invalid).toHaveLength(1)
    expect(saved.invalid[0]?.name).toBe('Old')
    expect(saved.invalid[0]?.errors.join()).toContain('"border-width"')
    expect(JSON.parse(saved.invalid[0]?.json ?? '')).toEqual(old)
    expect(loadCustomThemes(store)).toEqual([])
  })

  it('adding and removing other themes leaves it in storage', () => {
    const { store, data } = seeded()
    const a = make('A')
    addCustomTheme(a, store)
    removeCustomTheme(make('Zed').id, store)
    const stored = JSON.parse(data.get(CUSTOM_THEMES_KEY) ?? '[]') as { name: string }[]
    expect(stored.map((e) => e.name)).toEqual(['A', 'Old'])
    removeCustomTheme(a.id, store)
    expect((JSON.parse(data.get(CUSTOM_THEMES_KEY) ?? '[]') as unknown[]).length).toBe(1)
  })

  it('it counts toward the limit of five, so a full set cannot be exceeded by hiding one', () => {
    const { store } = seeded()
    for (let i = 0; i < MAX_CUSTOM_THEMES - 1; i++)
      expect(addCustomTheme(make(`T${i}`), store).ok).toBe(true)
    expect(addCustomTheme(make('One more'), store).ok).toBe(false)
  })

  it('discarding removes only that entry', () => {
    const { store } = seeded()
    const a = make('A')
    addCustomTheme(a, store)
    const id = readSavedThemes(store).invalid[0]?.id ?? ''
    discardInvalidTheme(id, store)
    expect(readSavedThemes(store).invalid).toEqual([])
    expect(loadCustomThemes(store)).toEqual([a])
    discardInvalidTheme('invalid-nope', store)
    expect(loadCustomThemes(store)).toEqual([a])
  })

  it('a non-object entry is kept and named as an unnamed entry', () => {
    const { store } = memoryStore({ [CUSTOM_THEMES_KEY]: JSON.stringify([5, 'x']) })
    expect(readSavedThemes(store).invalid.map((i) => i.name)).toEqual([
      '(unnamed entry)',
      '(unnamed entry)',
    ])
  })

  describe('importing the fixed version of a broken entry repairs it', () => {
    const broken = { name: 'Moss', mode: 'dark', tokens: { 'border-width': '0' } }
    const seed = (entries: unknown[]) =>
      memoryStore({ [CUSTOM_THEMES_KEY]: JSON.stringify(entries) })

    it('at the limit, it replaces the broken one instead of being refused', () => {
      const { store } = seed(
        [make('A'), make('B'), make('C'), make('D'), broken].map((e) =>
          'tokens' in e && 'mode' in e ? { name: e.name, mode: e.mode, tokens: e.tokens } : e,
        ),
      )
      const fixed = make('Moss', { 'border-width': '1px' })
      const r = addCustomTheme(fixed, store)
      expect(r.ok && r.replaced).toBe(true)
      const saved = readSavedThemes(store)
      expect(saved.invalid).toEqual([])
      expect(saved.valid.map((t) => t.name).sort()).toEqual(['A', 'B', 'C', 'D', 'Moss'])
    })

    it('below the limit, it leaves no stale copy and says it replaced one', () => {
      const { store } = seed([broken])
      const r = addCustomTheme(make('moss', { 'border-width': '1px' }), store)
      expect(r.ok && r.replaced).toBe(true)
      const saved = readSavedThemes(store)
      expect(saved.valid).toHaveLength(1)
      expect(saved.invalid).toEqual([])
    })

    it('a different broken entry is still kept and still counts toward the limit', () => {
      const other = { name: 'Other', mode: 'dark', tokens: { 'border-width': '0' } }
      const { store } = seed(
        [make('A'), make('B'), make('C'), other, broken].map((e) =>
          'tokens' in e && 'mode' in e ? { name: e.name, mode: e.mode, tokens: e.tokens } : e,
        ),
      )
      expect(addCustomTheme(make('Moss', { 'border-width': '1px' }), store).ok).toBe(true)
      expect(readSavedThemes(store).invalid.map((i) => i.name)).toEqual(['Other'])
      // Three valid, the fixed Moss and the other broken entry fill the five.
      expect(addCustomTheme(make('E'), store).ok).toBe(false)
      discardInvalidTheme(readSavedThemes(store).invalid[0]?.id ?? '', store)
      expect(addCustomTheme(make('E'), store).ok).toBe(true)
    })
  })

  it('replacing says so; a new name does not', () => {
    const { store } = memoryStore()
    const first = addCustomTheme(make('Mine'), store)
    expect(first.ok && first.replaced).toBe(false)
    const again = addCustomTheme(make('mine', { primary: 'oklch(0.8 0.1 90)' }), store)
    expect(again.ok && again.replaced).toBe(true)
  })
})
