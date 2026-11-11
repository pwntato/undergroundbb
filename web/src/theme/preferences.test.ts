import { describe, expect, it } from 'vitest'
import { MAX_CUSTOM_THEMES, validateCustomTheme, type CustomTheme } from './customTheme'
import {
  decodePreferences,
  encodePreferences,
  mergePreferences,
  samePreferences,
  type Preferences,
} from './preferences'

function make(name: string, over: Record<string, string> = {}): CustomTheme {
  const r = validateCustomTheme(JSON.stringify({ name, mode: 'dark', tokens: over }))
  if (!r.ok) throw new Error(r.errors.join())
  return r.theme
}

describe('the preferences document', () => {
  it('round-trips a choice and custom themes', () => {
    const prefs: Preferences = {
      themeId: make('Mine').id,
      customs: [make('Mine', { primary: 'oklch(0.8 0.1 150)' })],
    }
    const back = decodePreferences(encodePreferences(prefs))
    expect(back.ok && back.prefs).toEqual(prefs)
  })

  it('runs every theme in it through validation again, dropping the ones that fail', () => {
    const good = JSON.parse(JSON.stringify({ name: 'Good', mode: 'dark', tokens: {} })) as unknown
    const bad = {
      name: 'Bad',
      mode: 'dark',
      tokens: { primary: 'red; background: url(https://evil.example/x)' },
    }
    const worse = {
      name: 'Worse',
      mode: 'dark',
      tokens: { background: 'oklch(0.5 0 0)', foreground: 'oklch(0.5 0 0)' },
    }
    const text = JSON.stringify({ v: 1, theme: 'zine', customThemes: [bad, good, worse, 7, null] })
    const out = decodePreferences(text)
    expect(out.ok).toBe(true)
    if (!out.ok) return
    expect(out.prefs.customs.map((t) => t.name)).toEqual(['Good'])
    expect(out.prefs.themeId).toBe('zine')
  })

  it('reads at most the limit of custom themes and ignores a repeated one', () => {
    const many = Array.from({ length: 12 }, (_, i) => ({ name: `T${i}`, mode: 'dark', tokens: {} }))
    const out = decodePreferences(JSON.stringify({ v: 1, customThemes: [...many, many[0]] }))
    expect(out.ok && out.prefs.customs).toHaveLength(MAX_CUSTOM_THEMES)
  })

  it('refuses what it cannot read, and says a newer version is different from damage', () => {
    expect(decodePreferences('not json')).toEqual({ ok: false, reason: 'malformed' })
    expect(decodePreferences('[]')).toEqual({ ok: false, reason: 'malformed' })
    expect(decodePreferences('{"theme":"zine"}')).toEqual({ ok: false, reason: 'malformed' })
    expect(decodePreferences('{"v":2,"theme":"zine"}')).toEqual({
      ok: false,
      reason: 'unsupported-version',
    })
  })

  it('takes a theme id only if it is a plausible string', () => {
    for (const theme of [5, null, '', 'x'.repeat(81), { a: 1 }]) {
      const out = decodePreferences(JSON.stringify({ v: 1, theme }))
      expect(out.ok && out.prefs.themeId).toBeNull()
    }
  })
})

describe('mergePreferences', () => {
  const a = make('Alpha')
  const b = make('Beta')
  const aEdited = make('Alpha', { primary: 'oklch(0.8 0.1 150)' })

  it('the winner chooses the theme and its copy of a same-named theme; the lists are joined', () => {
    const local: Preferences = { themeId: 'zine', customs: [a] }
    const remote: Preferences = { themeId: 'bbs-revival', customs: [aEdited, b] }
    const r = mergePreferences(local, remote, 'remote')
    expect(r.themeId).toBe('bbs-revival')
    expect(r.customs.map((t) => t.name)).toEqual(['Alpha', 'Beta'])
    expect(r.customs[0]).toEqual(aEdited)
    const l = mergePreferences(local, remote, 'local')
    expect(l.themeId).toBe('zine')
    expect(l.customs[0]).toEqual(a)
    expect(l.customs.map((t) => t.name)).toEqual(['Alpha', 'Beta'])
  })

  it('falls to the other side when the winner names a theme that does not exist', () => {
    const r = mergePreferences(
      { themeId: 'zine', customs: [] },
      { themeId: 'no-such-theme', customs: [] },
      'remote',
    )
    expect(r.themeId).toBe('zine')
    expect(
      mergePreferences({ themeId: null, customs: [] }, { themeId: 'x', customs: [] }, 'remote')
        .themeId,
    ).toBeNull()
  })

  it('keeps a custom theme choice only while that theme is in the merged set', () => {
    const r = mergePreferences(
      { themeId: null, customs: [] },
      { themeId: b.id, customs: [b] },
      'remote',
    )
    expect(r.themeId).toBe(b.id)
  })

  it('caps the joined list at the limit, the winner first', () => {
    const local = { themeId: null, customs: Array.from({ length: 5 }, (_, i) => make(`L${i}`)) }
    const remote = { themeId: null, customs: Array.from({ length: 5 }, (_, i) => make(`R${i}`)) }
    const r = mergePreferences(local, remote, 'remote')
    expect(r.customs.map((t) => t.name)).toEqual(['R0', 'R1', 'R2', 'R3', 'R4'])
  })

  it('samePreferences compares what would be stored', () => {
    expect(
      samePreferences({ themeId: 'zine', customs: [a] }, { themeId: 'zine', customs: [a] }),
    ).toBe(true)
    expect(
      samePreferences({ themeId: 'zine', customs: [a] }, { themeId: 'zine', customs: [b] }),
    ).toBe(false)
    expect(samePreferences({ themeId: 'zine', customs: [] }, { themeId: null, customs: [] })).toBe(
      false,
    )
  })
})
