import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { contrastRatio, translucentContrast } from '../contrast'
import { themeProblems } from '../themeChecks'
import { TOKEN_NAMES, headingPairProblem } from '../tokens'
import { refinedTerminal } from './refinedTerminal'

const css = readFileSync(join(__dirname, '..', '..', 'index.css'), 'utf8')
const rootBlock = /:root\s*\{([^}]*)\}/.exec(css)?.[1] ?? ''
const declared = new Map(
  [...rootBlock.matchAll(/--ubb-([a-z-]+)\s*:\s*([^;]+);/g)].map((m) => [
    m[1],
    m[2]?.replace(/\s+/g, ' ').trim(),
  ]),
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

  it('meets everything a built-in theme must: every token, legal pairs, readable text, visible ring', () => {
    expect(themeProblems(refinedTerminal)).toEqual([])
  })

  it('keeps the focus ring visible at full strength and as the 50% halo components draw (3:1)', () => {
    const t = refinedTerminal
    const ring = t['ring'] ?? ''
    for (const ground of ['background', 'card']) {
      const g = t[ground] ?? ''
      expect(contrastRatio(ring, g), `ring on ${ground}`).toBeGreaterThanOrEqual(3)
      expect(translucentContrast(ring, g, 0.5), `ring/50 on ${ground}`).toBeGreaterThanOrEqual(3)
    }
  })

  it('keeps borders visible against the ground (1.3:1; control edges are for #54)', () => {
    const t = refinedTerminal
    expect(contrastRatio(t['border'] ?? '', t['background'] ?? '')).toBeGreaterThanOrEqual(1.3)
  })
})

describe('translucentContrast', () => {
  it('is the plain ratio at full strength and 1 at no strength', () => {
    const a = 'oklch(0.8 0.09 195)'
    const b = 'oklch(0.17 0.014 255)'
    expect(translucentContrast(a, b, 1)).toBeCloseTo(contrastRatio(a, b), 5)
    expect(translucentContrast(a, b, 0)).toBeCloseTo(1, 5)
  })
})

describe('contrastRatio', () => {
  it('matches known values', () => {
    expect(contrastRatio('oklch(1 0 0)', 'oklch(0 0 0)')).toBeCloseTo(21, 0)
    expect(contrastRatio('oklch(0.5 0 0)', 'oklch(0.5 0 0)')).toBeCloseTo(1, 5)
  })
})
