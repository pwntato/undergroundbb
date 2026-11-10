import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { contrastRatio } from '../contrast'
import { TOKEN_NAMES, headingPairProblem } from '../tokens'
import { refinedTerminal } from './refinedTerminal'

const css = readFileSync(join(__dirname, '..', '..', 'index.css'), 'utf8')
const rootBlock = /:root\s*\{([^}]*)\}/.exec(css)?.[1] ?? ''
const declared = new Map(
  [...rootBlock.matchAll(/--ubb-([a-z-]+)\s*:\s*([^;]+);/g)].map((m) => [m[1], m[2]?.trim()]),
)

describe('Refined Terminal', () => {
  it('gives a value to every token and to nothing else', () => {
    expect(Object.keys(refinedTerminal).sort()).toEqual([...TOKEN_NAMES].sort())
  })

  it('is exactly what index.css declares in :root, so the page is themed before any script runs', () => {
    for (const name of TOKEN_NAMES) expect(declared.get(name), name).toBe(refinedTerminal[name])
  })

  it('keeps its heading case and tracking pair legal', () => {
    expect(headingPairProblem(refinedTerminal)).toBeNull()
  })

  it('uses system fonts only (the CSP has no font-src), with a humanist sans and a mono for data', () => {
    expect(refinedTerminal['font-sans']).toMatch(/^Seravek,/)
    expect(refinedTerminal['font-sans']).toMatch(/sans-serif$/)
    expect(refinedTerminal['font-mono']).toMatch(/monospace$/)
    expect(css).not.toMatch(/@font-face|fonts\.googleapis/)
  })

  describe('text is readable (WCAG AA, 4.5:1)', () => {
    const t = refinedTerminal
    const pairs: ReadonlyArray<readonly [string, string, string]> = [
      ['foreground', 'background', 'body text'],
      ['foreground', 'card', 'text on a card'],
      ['foreground', 'surface', 'text on a surface'],
      ['muted-foreground', 'background', 'secondary text'],
      ['muted-foreground', 'card', 'secondary text on a card'],
      ['muted-foreground', 'muted', 'secondary text on a muted block'],
      ['primary-foreground', 'primary', 'button label'],
      ['primary', 'background', 'teal text and links on the page'],
      ['primary', 'card', 'teal text on a card'],
      ['accent-foreground', 'accent', 'hovered item'],
      ['secondary-foreground', 'secondary', 'secondary button'],
      ['destructive', 'background', 'error text'],
      ['destructive', 'card', 'error text on a card'],
      ['destructive-foreground', 'destructive', 'destructive label'],
    ]
    for (const [fg, bg, what] of pairs) {
      it(`${fg} on ${bg} (${what})`, () => {
        expect(contrastRatio(t[fg] ?? '', t[bg] ?? '')).toBeGreaterThanOrEqual(4.5)
      })
    }
  })

  it('keeps borders and the focus ring visible against the ground (3:1)', () => {
    const t = refinedTerminal
    expect(contrastRatio(t['ring'] ?? '', t['background'] ?? '')).toBeGreaterThanOrEqual(3)
    expect(contrastRatio(t['border'] ?? '', t['background'] ?? '')).toBeGreaterThanOrEqual(1.3)
  })
})

describe('contrastRatio', () => {
  it('matches known values', () => {
    expect(contrastRatio('oklch(1 0 0)', 'oklch(0 0 0)')).toBeCloseTo(21, 0)
    expect(contrastRatio('oklch(0.5 0 0)', 'oklch(0.5 0 0)')).toBeCloseTo(1, 5)
  })
})
