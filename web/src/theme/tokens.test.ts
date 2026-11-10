import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { CASE_VALUES, TOKENS, TOKEN_NAMES, headingPairProblem } from './tokens'

const css = readFileSync(join(__dirname, '..', 'index.css'), 'utf8')
const rootBlock = /:root\s*\{([^}]*)\}/.exec(css)?.[1] ?? ''
const themeBlock = /@theme\s*\{([^}]*)\}/.exec(css)?.[1] ?? ''

describe('the token vocabulary', () => {
  it('has no duplicate names and every custom property is --ubb-<name>', () => {
    expect(new Set(TOKEN_NAMES).size).toBe(TOKEN_NAMES.length)
    for (const t of TOKENS) expect(t.cssVar).toBe(`--ubb-${t.name}`)
  })

  it('has a default declared in :root for every token', () => {
    for (const t of TOKENS) {
      expect(rootBlock, t.cssVar).toMatch(new RegExp(`${t.cssVar}\\s*:`))
    }
  })

  it('declares nothing in :root that the vocabulary does not list', () => {
    const declared = [...rootBlock.matchAll(/(--ubb-[a-z-]+)\s*:/g)].map((m) => m[1])
    const listed = new Set(TOKENS.map((t) => t.cssVar))
    expect(declared.filter((v) => !listed.has(v ?? ''))).toEqual([])
  })

  it('is used: every token is read by the Tailwind theme or the base rules', () => {
    const used = css.slice(css.indexOf('@theme'))
    for (const t of TOKENS) {
      const reads = used.match(new RegExp(`var\\(${t.cssVar}\\)`, 'g')) ?? []
      // font-heading is read by the theme map and by the base rules; every token needs at least one.
      expect(reads.length, t.cssVar).toBeGreaterThan(0)
    }
    expect(themeBlock).toContain('--color-card: var(--ubb-card)')
  })

  it('covers what Zine needs: hard shadow, zero radius, thick border, uppercase heading', () => {
    const names = new Set(TOKEN_NAMES)
    for (const need of [
      'shadow-md',
      'radius-md',
      'border-width',
      'border-width-strong',
      'case-heading',
      'tracking-heading',
      'font-heading',
    ]) {
      expect(names.has(need), need).toBe(true)
    }
  })
})

describe('headingPairProblem', () => {
  const upper = (tracking?: string) =>
    headingPairProblem({
      'case-heading': 'uppercase',
      ...(tracking === undefined ? {} : { 'tracking-heading': tracking }),
    })

  it('refuses uppercase headings whose spacing is missing, zero or not above zero', () => {
    for (const t of [
      undefined,
      '',
      '0',
      '0em',
      '0px',
      '0.0em',
      '0rem',
      '0%',
      'normal',
      '-0.02em',
      '-1px',
    ]) {
      expect(upper(t), String(t)).not.toBeNull()
    }
  })

  it('refuses spacing that is not a plain length', () => {
    for (const t of ['0.08', 'calc(1em)', 'var(--x)', '1e-3em', '5%', '.em', 'em']) {
      expect(upper(t), t).not.toBeNull()
    }
  })

  it('accepts uppercase with positive spacing, and any spacing without uppercase', () => {
    for (const t of ['0.08em', '.05em', '1px', '0.1rem']) expect(upper(t), t).toBeNull()
    expect(headingPairProblem({ 'case-heading': 'none' })).toBeNull()
    expect(headingPairProblem({ 'case-heading': 'none', 'tracking-heading': '-0.02em' })).toBeNull()
    expect(headingPairProblem({})).toBeNull()
  })

  it('lists the allowed case values', () => {
    expect([...CASE_VALUES]).toEqual(['none', 'uppercase', 'lowercase', 'capitalize'])
  })
})
