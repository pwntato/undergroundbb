import { describe, expect, it } from 'vitest'
import {
  MAX_THEME_TEXT,
  customThemeId,
  exportThemeJson,
  tokenValue,
  validateCustomTheme,
} from './customTheme'
import { BUILT_IN_THEMES } from './themes'
import { TOKEN_NAMES } from './tokens'

const theme = (over: Record<string, unknown> = {}, top: Record<string, unknown> = {}) =>
  JSON.stringify({ name: 'Mine', mode: 'dark', tokens: over, ...top })

describe('every built-in theme is a valid custom theme', () => {
  for (const t of BUILT_IN_THEMES) {
    it(`${t.name} imports, and importing its export again changes nothing`, () => {
      const first = validateCustomTheme(exportThemeJson(t))
      expect(first.ok).toBe(true)
      if (!first.ok) return
      // Only font stacks are rewritten (each name quoted); every other value comes back as written.
      for (const name of TOKEN_NAMES) {
        if (!name.startsWith('font-')) expect(first.theme.tokens[name]).toBe(t.tokens[name])
      }
      const second = validateCustomTheme(exportThemeJson(first.theme))
      expect(second.ok && second.theme.tokens).toEqual(first.theme.tokens)
    })
  }
})

describe('missing tokens come from the built-in of the same mode', () => {
  it('a dark theme with one token set is Refined Terminal plus that token', () => {
    const r = validateCustomTheme(theme({ primary: 'oklch(0.8 0.1 150)' }))
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.theme.tokens['primary']).toBe('oklch(0.8 0.1 150)')
    expect(r.theme.tokens['background']).toBe(BUILT_IN_THEMES[0]?.tokens['background'])
    expect(r.theme.mode).toBe('dark')
    expect(r.theme.custom).toBe(true)
  })
  it('a light theme starts from Zine', () => {
    const r = validateCustomTheme(theme({}, { mode: 'light' }))
    expect(r.ok && r.theme.tokens['background']).toBe(BUILT_IN_THEMES[2]?.tokens['background'])
  })
})

describe('the shape of the document', () => {
  const refused = (text: string) => {
    const r = validateCustomTheme(text)
    expect(r.ok).toBe(false)
    return r.ok ? [] : r.errors
  }
  it('refuses text that is not JSON, not an object, or too long', () => {
    expect(refused('{nope')).toEqual(['This is not valid JSON.'])
    expect(refused('[1]')[0]).toContain('JSON object')
    expect(refused('"x"')[0]).toContain('JSON object')
    expect(refused(' '.repeat(MAX_THEME_TEXT + 1))[0]).toContain('too long')
  })
  it('refuses an unknown top-level field, a bad name and a bad mode', () => {
    expect(refused(theme({}, { css: 'a{}' })).join()).toContain('Unknown field "css"')
    expect(refused(theme({}, { name: '' })).join()).toContain('"name"')
    expect(refused(theme({}, { name: 'a<b' })).join()).toContain('"name"')
    expect(refused(theme({}, { name: 'x'.repeat(41) })).join()).toContain('"name"')
    expect(refused(theme({}, { mode: 'blue' })).join()).toContain('"mode"')
    expect(refused(theme({}, { tokens: [] })).join()).toContain('"tokens"')
  })
  it('refuses an unknown token, however it is spelled', () => {
    expect(refused(theme({ position: 'fixed' })).join()).toContain('Unknown token "position"')
    expect(refused(theme({ 'z-index': '9999' })).join()).toContain('Unknown token')
    expect(refused(theme({ __proto__x: 'a' })).join()).toContain('Unknown token')
  })
  it('a __proto__ key in the JSON is an unknown token, not a prototype write', () => {
    const r = validateCustomTheme(
      '{"name":"A","mode":"dark","tokens":{"__proto__":{"primary":"x"}}}',
    )
    expect(r.ok).toBe(false)
    expect(({} as Record<string, unknown>)['primary']).toBeUndefined()
  })
})

describe('colors', () => {
  const good = (v: string) => tokenValue('primary', v)
  it('accepts a plain oklch() and rebuilds it', () => {
    expect(good('oklch(0.5 0.2 27)')).toBe('oklch(0.5 0.2 27)')
    expect(good('oklch( 0.50   0.200  27.0 )')).toBe('oklch(0.5 0.2 27)')
  })
  it.each([
    'red',
    '#fff',
    'rgb(0 0 0)',
    'oklch(0.5 0.2 27 / 0.5)',
    'oklch(2 0.2 27)',
    'oklch(0.5 0.9 27)',
    'oklch(0.5 0.2 400)',
    'oklch(0.5 0.2 27); background: url(x)',
    'oklch(0.5 0.2 27)/**/',
    'oklch(0.5 0.2 var(--x))',
    'oklch(1e1 0 0)',
    'oklch(-1 0 0)',
    'url(https://evil.example/x)',
    'oklch(0.5 0.2 27) !important',
    '',
  ])('refuses %j', (v) => {
    expect(good(v)).toBeNull()
  })
  it('refuses a non-string', () => {
    expect(tokenValue('primary', 5)).toBeNull()
    expect(tokenValue('primary', null)).toBeNull()
    expect(tokenValue('primary', { toString: () => 'oklch(0 0 0)' })).toBeNull()
  })
})

describe('lengths', () => {
  it('accepts values in range and rebuilds them', () => {
    expect(tokenValue('radius-md', '0.5rem')).toBe('0.5rem')
    expect(tokenValue('radius-md', '0')).toBe('0')
    expect(tokenValue('border-width-strong', '3px')).toBe('3px')
    expect(tokenValue('spacing', '0.2rem')).toBe('0.2rem')
    expect(tokenValue('tracking-heading', '0.08em')).toBe('0.08em')
  })
  it.each([
    ['radius-md', '33px'],
    ['radius-md', '3rem'],
    ['radius-md', '-1px'],
    ['radius-md', '50%'],
    ['radius-md', 'calc(1px + 1px)'],
    ['radius-md', '1'],
    ['radius-md', 'var(--x)'],
    ['radius-md', '1px 2px'],
    ['border-width', '5px'],
    ['border-width-strong', '13px'],
    ['spacing', '0.1rem'],
    ['spacing', '0.5rem'],
    ['spacing', '0'],
    ['tracking-body', '0.4em'],
    ['tracking-body', '-0.05em'],
  ])('refuses %s: %j', (name, v) => {
    expect(tokenValue(name, v)).toBeNull()
  })
})

describe('shadows', () => {
  it('accepts the shapes the built-in themes use, rebuilt', () => {
    expect(tokenValue('shadow-sm', '0 0 0 0 transparent')).toBe('0 0 0 0 transparent')
    expect(tokenValue('shadow-sm', '3px 3px 0 0 oklch(0.16 0.006 80)')).toBe(
      '3px 3px 0 0 oklch(0.16 0.006 80)',
    )
    expect(tokenValue('shadow-md', '0 4px 6px -1px oklch(0 0 0 / 0.4)')).toBe(
      '0 4px 6px -1px oklch(0 0 0 / 0.4)',
    )
    expect(tokenValue('shadow-md', '1px 1px 2px oklch(0 0 0), 0 0 0 0 transparent')).toBe(
      '1px 1px 2px oklch(0 0 0), 0 0 0 0 transparent',
    )
  })
  it.each([
    'none',
    '0 0 0 0 red',
    'inset 0 0 0 0 transparent',
    '0 0 0 0 transparent; x: y',
    '0 0 0 0 url(x)',
    '100px 0 0 0 transparent',
    '0 0 99px 0 transparent',
    '1rem 0 0 0 transparent',
    '0 0 0 0 oklch(0 0 0 / 2)',
    '0 0 0 0 oklch(0 0 0 / x)',
    '0 0 0 0 oklch(0 0 0 / 0.5) extra',
    '0 0 0 0 transparent, 0 0 0 0 transparent, 0 0 0 0 transparent, 0 0 0 0 transparent',
  ])('refuses %j', (v) => {
    expect(tokenValue('shadow-sm', v)).toBeNull()
  })
})

describe('fonts', () => {
  it('accepts generic families and plain names, and quotes the names itself', () => {
    expect(tokenValue('font-sans', 'Helvetica Neue, Arial, sans-serif')).toBe(
      "'Helvetica Neue', 'Arial', sans-serif",
    )
    expect(tokenValue('font-mono', "'JetBrains Mono', ui-monospace")).toBe(
      "'JetBrains Mono', ui-monospace",
    )
  })
  it('accepts the one fixed reference only on the heading font', () => {
    expect(tokenValue('font-heading', 'var(--ubb-font-sans)')).toBe('var(--ubb-font-sans)')
    expect(tokenValue('font-sans', 'var(--ubb-font-sans)')).toBeNull()
    expect(tokenValue('font-heading', 'var(--ubb-font-mono)')).toBeNull()
  })
  it.each([
    "Arial'; background: url(x); '",
    'Arial; color: red',
    'url(https://evil.example/f.woff)',
    'local(Arial)',
    'Arial } body { display: none',
    'inherit',
    'Arial, inherit',
    'a,b,c,d,e,f,g,h,i,j,k',
    'x'.repeat(60),
    '',
    'Ar\\ial',
    'Arial /* c */',
    '@import',
  ])('refuses %j', (v) => {
    expect(tokenValue('font-sans', v)).toBeNull()
  })
})

describe('keyword tokens', () => {
  it('only the listed values', () => {
    expect(tokenValue('border-style', 'double')).toBe('double')
    expect(tokenValue('border-style', 'groove')).toBeNull()
    expect(tokenValue('case-heading', 'uppercase')).toBe('uppercase')
    expect(tokenValue('case-heading', 'full-width')).toBeNull()
  })
})

describe('the accessibility floor the built-ins meet', () => {
  it('refuses text that cannot be read, and says which pair', () => {
    const r = validateCustomTheme(theme({ foreground: 'oklch(0.2 0.01 255)' }))
    expect(r.ok).toBe(false)
    expect(r.ok ? '' : r.errors.join('\n')).toContain('foreground on background')
  })
  it('refuses uppercase headings with no letter-spacing', () => {
    const r = validateCustomTheme(theme({ 'case-heading': 'uppercase', 'tracking-heading': '0em' }))
    expect(r.ok).toBe(false)
    expect(r.ok ? '' : r.errors.join('\n')).toContain('letter-spacing')
  })
  it('accepts the same theme once the letter-spacing is there', () => {
    expect(
      validateCustomTheme(theme({ 'case-heading': 'uppercase', 'tracking-heading': '0.05em' })).ok,
    ).toBe(true)
  })
  it('refuses a focus ring that disappears into the page', () => {
    const r = validateCustomTheme(theme({ ring: 'oklch(0.2 0.01 255)' }))
    expect(r.ok).toBe(false)
  })
})

describe('ids', () => {
  it('one name is one id, different names differ, and the id is made of safe characters', () => {
    expect(customThemeId('Mine')).toBe(customThemeId('Mine'))
    expect(customThemeId('Mine')).not.toBe(customThemeId('mine'))
    expect(customThemeId('日本語')).toMatch(/^custom-theme-[a-z0-9]+$/)
    expect(customThemeId('A <b> & c')).toMatch(/^custom-[a-z0-9-]+$/)
  })
  it('covers every token in an export', () => {
    const r = validateCustomTheme(theme())
    expect(r.ok && Object.keys(r.theme.tokens).sort()).toEqual([...TOKEN_NAMES].sort())
  })
})
