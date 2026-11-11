import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  THEME_STORAGE_KEY,
  applyTheme,
  saveThemeId,
  storedTheme,
  switchTheme,
  type ThemeStore,
  type ThemeTarget,
} from './applyTheme'
import { contrastRatio } from './contrast'
import { themeProblems } from './themeChecks'
import { BUILT_IN_THEMES, DEFAULT_THEME, findTheme } from './themes'
import { TOKEN_NAMES } from './tokens'

function fakeRoot(): ThemeTarget & { props: Map<string, string>; attrs: Map<string, string> } {
  const props = new Map<string, string>()
  const attrs = new Map<string, string>()
  return {
    props,
    attrs,
    style: { setProperty: (n, v) => void props.set(n, v) },
    setAttribute: (n, v) => void attrs.set(n, v),
  }
}

function fakeStore(
  initial: Record<string, string> = {},
): ThemeStore & { data: Map<string, string> } {
  const data = new Map(Object.entries(initial))
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => void data.set(k, v),
  }
}

const throwing: ThemeStore = {
  getItem: () => {
    throw new Error('blocked')
  },
  setItem: () => {
    throw new Error('blocked')
  },
}

describe('the built-in theme list', () => {
  it('lists the three themes with unique ids, default first', () => {
    expect(BUILT_IN_THEMES.map((t) => t.id)).toEqual(['refined-terminal', 'bbs-revival', 'zine'])
    expect(DEFAULT_THEME.id).toBe('refined-terminal')
  })

  it('every theme passes the built-in checks', () => {
    for (const t of BUILT_IN_THEMES) expect(themeProblems(t.tokens), t.id).toEqual([])
  })

  it('declares the mode the ground colour actually is, so dark: classes fire only on dark themes', () => {
    for (const t of BUILT_IN_THEMES) {
      const ground = t.tokens['background'] ?? ''
      const light = contrastRatio(ground, 'oklch(0 0 0)') > contrastRatio(ground, 'oklch(1 0 0)')
      expect(t.mode, t.id).toBe(light ? 'light' : 'dark')
    }
  })

  it('index.html starts in the default theme mode, so the page is right before any script runs', () => {
    const html = readFileSync(join(__dirname, '..', '..', 'index.html'), 'utf8')
    expect(/<html[^>]*data-theme="([a-z]+)"/.exec(html)?.[1]).toBe(DEFAULT_THEME.mode)
  })
})

describe('applyTheme', () => {
  it('writes every token as a --ubb-* property and the mode as data-theme', () => {
    const root = fakeRoot()
    const zine = findTheme('zine')!
    applyTheme(zine, root)
    expect([...root.props.keys()].sort()).toEqual(TOKEN_NAMES.map((n) => `--ubb-${n}`).sort())
    for (const n of TOKEN_NAMES) expect(root.props.get(`--ubb-${n}`), n).toBe(zine.tokens[n])
    expect(root.attrs.get('data-theme')).toBe('light')
  })

  it('switching away leaves nothing of the old theme: the second theme overwrites every property', () => {
    const root = fakeRoot()
    applyTheme(findTheme('zine')!, root)
    applyTheme(findTheme('bbs-revival')!, root)
    for (const n of TOKEN_NAMES)
      expect(root.props.get(`--ubb-${n}`), n).toBe(findTheme('bbs-revival')!.tokens[n])
    expect(root.attrs.get('data-theme')).toBe('dark')
  })
})

describe('storedTheme', () => {
  it('returns the saved theme', () => {
    expect(storedTheme(fakeStore({ [THEME_STORAGE_KEY]: 'zine' })).id).toBe('zine')
  })

  it('falls back to the default for nothing saved, an unknown id, no store, or a store that throws', () => {
    expect(storedTheme(fakeStore()).id).toBe(DEFAULT_THEME.id)
    expect(storedTheme(fakeStore({ [THEME_STORAGE_KEY]: 'nope' })).id).toBe(DEFAULT_THEME.id)
    expect(storedTheme(fakeStore({ [THEME_STORAGE_KEY]: '__proto__' })).id).toBe(DEFAULT_THEME.id)
    expect(storedTheme(null).id).toBe(DEFAULT_THEME.id)
    expect(storedTheme(throwing).id).toBe(DEFAULT_THEME.id)
  })
})

describe('switchTheme', () => {
  it('applies the theme and remembers it', () => {
    const root = fakeRoot()
    const store = fakeStore()
    expect(switchTheme('zine', root, store)).toBe(true)
    expect(root.attrs.get('data-theme')).toBe('light')
    expect(store.data.get(THEME_STORAGE_KEY)).toBe('zine')
  })

  it('still applies when storage is blocked or missing', () => {
    for (const store of [throwing, null]) {
      const root = fakeRoot()
      expect(switchTheme('bbs-revival', root, store)).toBe(true)
      expect(root.props.get('--ubb-spacing')).toBe(findTheme('bbs-revival')!.tokens['spacing'])
    }
  })

  it('refuses an unknown id: nothing is applied and nothing is saved', () => {
    const root = fakeRoot()
    const store = fakeStore()
    expect(switchTheme('nope', root, store)).toBe(false)
    expect(root.props.size).toBe(0)
    expect(root.attrs.size).toBe(0)
    expect(store.data.size).toBe(0)
  })

  it('a saved choice survives a reload: what was saved is what storedTheme returns', () => {
    const store = fakeStore()
    switchTheme('bbs-revival', fakeRoot(), store)
    expect(storedTheme(store).id).toBe('bbs-revival')
  })
})

describe('saveThemeId', () => {
  it('reports whether it saved, and refuses ids that are not built-in', () => {
    const store = fakeStore()
    expect(saveThemeId('zine', store)).toBe(true)
    expect(saveThemeId('evil', store)).toBe(false)
    expect(saveThemeId('zine', throwing)).toBe(false)
    expect(saveThemeId('zine', null)).toBe(false)
    expect(store.data.get(THEME_STORAGE_KEY)).toBe('zine')
  })
})
