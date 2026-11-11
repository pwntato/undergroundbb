import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import {
  THEME_STORAGE_KEY,
  applyStoredTheme,
  appliedThemeId,
  applyTheme,
  pickTheme,
  THEME_ID_ATTRIBUTE,
  saveThemeId,
  storedTheme,
  switchTheme,
  forgetCustomTheme,
  type ThemeStore,
  type ThemeTarget,
} from './applyTheme'
import { contrastRatio } from './contrast'
import { validateCustomTheme } from './customTheme'
import { CUSTOM_THEMES_KEY, addCustomTheme, loadCustomThemes } from './customThemes'
import { themeProblems } from './themeChecks'
import { BUILT_IN_THEMES, DEFAULT_THEME, findTheme } from './themes'
import { TOKEN_NAMES } from './tokens'

function fakeRoot(): ThemeTarget & {
  props: Map<string, string>
  attrs: Map<string, string>
  getAttribute(n: string): string | null
} {
  const props = new Map<string, string>()
  const attrs = new Map<string, string>()
  return {
    props,
    attrs,
    style: { setProperty: (n, v) => void props.set(n, v) },
    setAttribute: (n, v) => void attrs.set(n, v),
    getAttribute: (n: string) => attrs.get(n) ?? null,
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

describe('applyStoredTheme (what runs at startup)', () => {
  it('puts the saved theme on the page', () => {
    const root = fakeRoot()
    expect(applyStoredTheme(root, fakeStore({ [THEME_STORAGE_KEY]: 'zine' })).id).toBe('zine')
    expect(root.attrs.get('data-theme')).toBe('light')
    expect(root.props.get('--ubb-border-width-strong')).toBe(
      findTheme('zine')!.tokens['border-width-strong'],
    )
  })

  it('puts the default on the page when nothing usable is saved', () => {
    for (const store of [fakeStore(), fakeStore({ [THEME_STORAGE_KEY]: 'nope' }), throwing, null]) {
      const root = fakeRoot()
      expect(applyStoredTheme(root, store).id).toBe(DEFAULT_THEME.id)
      expect(root.props.get('--ubb-background')).toBe(DEFAULT_THEME.tokens['background'])
    }
  })
})

describe('appliedThemeId', () => {
  it('reads the theme on the page, whatever storage says', () => {
    const root = fakeRoot()
    switchTheme('zine', root, throwing)
    expect(root.attrs.get(THEME_ID_ATTRIBUTE)).toBe('zine')
    expect(appliedThemeId(root)).toBe('zine')
    switchTheme('bbs-revival', root, null)
    expect(appliedThemeId(root)).toBe('bbs-revival')
  })

  it('is the default before anything is applied, or when the attribute is not a built-in id', () => {
    const root = fakeRoot()
    expect(appliedThemeId(root)).toBe(DEFAULT_THEME.id)
    root.setAttribute(THEME_ID_ATTRIBUTE, '__proto__')
    expect(appliedThemeId(root)).toBe(DEFAULT_THEME.id)
  })
})

describe('pickTheme', () => {
  it('switches, saves, and returns the new current id', () => {
    const root = fakeRoot()
    const store = fakeStore()
    expect(pickTheme('zine', 'refined-terminal', root, store)).toBe('zine')
    expect(root.attrs.get('data-theme')).toBe('light')
    expect(store.data.get(THEME_STORAGE_KEY)).toBe('zine')
  })

  it('leaves the page, the store and the current id alone for an unknown id', () => {
    const root = fakeRoot()
    const store = fakeStore()
    expect(pickTheme('nope', 'bbs-revival', root, store)).toBe('bbs-revival')
    expect(root.attrs.size).toBe(0)
    expect(store.data.size).toBe(0)
  })

  it('returns the new id even when storage is blocked, because the page did switch', () => {
    expect(pickTheme('zine', 'refined-terminal', fakeRoot(), throwing)).toBe('zine')
  })
})

describe('custom themes at startup and in the store (#74)', () => {
  const custom = () => {
    const r = validateCustomTheme(
      JSON.stringify({ name: 'Mine', mode: 'light', tokens: { primary: 'oklch(0.4 0.15 150)' } }),
    )
    if (!r.ok) throw new Error('bad fixture')
    return r.theme
  }
  const withCustom = () => {
    const data = new Map<string, string>()
    const store: ThemeStore = {
      getItem: (k) => data.get(k) ?? null,
      setItem: (k, v) => void data.set(k, v),
    }
    const t = custom()
    addCustomTheme(t, store)
    return { data, store, t }
  }

  it('a saved custom theme id is applied at startup, with its mode', () => {
    const { store, t } = withCustom()
    store.setItem(THEME_STORAGE_KEY, t.id)
    const attrs = new Map<string, string>()
    const props = new Map<string, string>()
    const applied = applyStoredTheme(
      {
        style: { setProperty: (n, v) => void props.set(n, v) },
        setAttribute: (n, v) => void attrs.set(n, v),
      },
      store,
    )
    expect(applied.id).toBe(t.id)
    expect(attrs.get('data-theme')).toBe('light')
    expect(props.get('--ubb-primary')).toBe('oklch(0.4 0.15 150)')
  })

  it('a custom id whose theme is gone, or was damaged in storage, falls back to the default', () => {
    const { store, data, t } = withCustom()
    store.setItem(THEME_STORAGE_KEY, t.id)
    data.set(
      CUSTOM_THEMES_KEY,
      JSON.stringify([{ name: 'Mine', mode: 'light', tokens: { primary: 'url(//x)' } }]),
    )
    expect(storedTheme(store).id).toBe('refined-terminal')
    data.delete(CUSTOM_THEMES_KEY)
    expect(storedTheme(store).id).toBe('refined-terminal')
  })

  it('a custom id is only remembered or switched to if the theme exists', () => {
    const { store, t } = withCustom()
    expect(saveThemeId(t.id, store)).toBe(true)
    expect(saveThemeId('custom-nope-1', store)).toBe(false)
    const target = { style: { setProperty: () => undefined }, setAttribute: () => undefined }
    expect(switchTheme(t.id, target, store)).toBe(true)
    expect(switchTheme('custom-nope-1', target, store)).toBe(false)
  })

  it('appliedThemeId knows a custom theme only when it is told about it', () => {
    const t = custom()
    const root = { getAttribute: () => t.id }
    expect(appliedThemeId(root)).toBe('refined-terminal')
    expect(appliedThemeId(root, [t])).toBe(t.id)
  })

  it('forgetting the showing theme switches back to the default; another leaves it', () => {
    const { store, t } = withCustom()
    const attrs = new Map<string, string>()
    const target = {
      style: { setProperty: () => undefined },
      setAttribute: (n: string, v: string) => void attrs.set(n, v),
    }
    expect(forgetCustomTheme(t.id, 'zine', target, store)).toBe('zine')
    addCustomTheme(t, store)
    expect(forgetCustomTheme(t.id, t.id, target, store)).toBe('refined-terminal')
    expect(attrs.get('data-theme-id')).toBe('refined-terminal')
    expect(loadCustomThemes(store)).toEqual([])
  })
})
