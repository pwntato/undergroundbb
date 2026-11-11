import { describe, expect, it } from 'vitest'
import { THEME_STORAGE_KEY } from '@/theme/applyTheme'
import { CUSTOM_THEMES_KEY } from '@/theme/customThemes'
import {
  initialAppearance,
  runExport,
  runImport,
  runRemove,
  runSelect,
  typeImport,
  type AppearanceEnv,
} from './appearanceState'

function env() {
  const attrs = new Map<string, string>()
  const props = new Map<string, string>()
  const data = new Map<string, string>()
  const e: AppearanceEnv = {
    target: {
      style: { setProperty: (n, v) => void props.set(n, v) },
      setAttribute: (n, v) => void attrs.set(n, v),
      getAttribute: (n) => attrs.get(n) ?? null,
    },
    store: { getItem: (k) => data.get(k) ?? null, setItem: (k, v) => void data.set(k, v) },
  }
  return { e, attrs, props, data }
}

const GOOD = JSON.stringify({
  name: 'Mine',
  mode: 'light',
  tokens: { primary: 'oklch(0.4 0.15 150)' },
})

describe('importing a custom theme', () => {
  it('keeps it, puts it on the page at once, and clears the box', () => {
    const { e, attrs, props, data } = env()
    const s = runImport(typeImport(initialAppearance(e), GOOD), e)
    expect(s.errors).toEqual([])
    expect(s.importText).toBe('')
    expect(s.customs.map((t) => t.name)).toEqual(['Mine'])
    expect(s.currentId).toBe(s.customs[0]?.id)
    expect(attrs.get('data-theme')).toBe('light')
    expect(attrs.get('data-theme-id')).toBe(s.currentId)
    expect(props.get('--ubb-primary')).toBe('oklch(0.4 0.15 150)')
    expect(data.get(THEME_STORAGE_KEY)).toBe(s.currentId)
    expect(data.has(CUSTOM_THEMES_KEY)).toBe(true)
  })

  it('a refused theme changes nothing on the page or in storage, and shows why', () => {
    const { e, attrs, data } = env()
    const before = initialAppearance(e)
    const bad = JSON.stringify({ name: 'Bad', mode: 'dark', tokens: { primary: 'url(//evil)' } })
    const s = runImport(typeImport(before, bad), e)
    expect(s.errors.join()).toContain('"primary"')
    expect(s.customs).toEqual([])
    expect(s.currentId).toBe(before.currentId)
    expect(s.importText).toBe(bad)
    expect(attrs.size).toBe(0)
    expect(data.size).toBe(0)
  })

  it('says so, and changes nothing, when the browser will not save', () => {
    const { e, attrs } = env()
    const blocked: AppearanceEnv = { ...e, store: null }
    const s = runImport(typeImport(initialAppearance(blocked), GOOD), blocked)
    expect(s.errors).toEqual(['This browser would not let the page save the theme.'])
    expect(s.customs).toEqual([])
    expect(attrs.size).toBe(0)
  })

  it('a theme that is later in storage is the starting state of the screen', () => {
    const { e } = env()
    const s = runImport(typeImport(initialAppearance(e), GOOD), e)
    const again = initialAppearance(e)
    expect(again.customs.map((t) => t.id)).toEqual([s.currentId])
    expect(again.currentId).toBe(s.currentId)
  })
})

describe('removing, selecting and exporting', () => {
  it('removing the theme that is showing brings back the default', () => {
    const { e, attrs, data } = env()
    const s = runImport(typeImport(initialAppearance(e), GOOD), e)
    const after = runRemove(s, s.currentId, e)
    expect(after.customs).toEqual([])
    expect(after.currentId).toBe('refined-terminal')
    expect(attrs.get('data-theme-id')).toBe('refined-terminal')
    expect(JSON.parse(data.get(CUSTOM_THEMES_KEY) ?? 'x')).toEqual([])
  })

  it('removing another theme leaves the one showing alone', () => {
    const { e } = env()
    const a = runImport(typeImport(initialAppearance(e), GOOD), e)
    const other = JSON.stringify({ name: 'Other', mode: 'dark', tokens: {} })
    const b = runImport(typeImport(a, other), e)
    const after = runRemove(b, a.currentId, e)
    expect(after.currentId).toBe(b.currentId)
    expect(after.customs.map((t) => t.name)).toEqual(['Other'])
  })

  it('selecting a custom card applies it; an unknown id changes nothing', () => {
    const { e, attrs } = env()
    const s = runImport(typeImport(initialAppearance(e), GOOD), e)
    const back = runSelect(s, 'zine', e)
    expect(back.currentId).toBe('zine')
    expect(attrs.get('data-theme-id')).toBe('zine')
    expect(runSelect(back, s.currentId, e).currentId).toBe(s.currentId)
    expect(runSelect(back, 'custom-nope-1', e)).toBe(back)
  })

  it('exports the showing theme as JSON that imports again; a built-in is offered as a copy', () => {
    const { e } = env()
    const start = runExport(initialAppearance(e))
    const json = JSON.parse(start.exportText ?? '{}') as { name: string }
    expect(json.name).toBe('Refined Terminal copy')
    const imported = runImport(typeImport(initialAppearance(e), start.exportText ?? ''), e)
    expect(imported.errors).toEqual([])
    expect(imported.customs[0]?.name).toBe('Refined Terminal copy')
    expect((JSON.parse(runExport(imported).exportText ?? '{}') as { name: string }).name).toBe(
      'Refined Terminal copy',
    )
  })

  it('typing is capped so a huge paste cannot be held in state', () => {
    const { e } = env()
    expect(typeImport(initialAppearance(e), 'x'.repeat(100000)).importText.length).toBeLessThan(
      10000,
    )
  })
})
