import { describe, expect, it } from 'vitest'
import { contrastRatio } from '../contrast'
import { themeProblems } from '../themeChecks'
import { bbsRevival } from './bbsRevival'

describe('BBS Revival', () => {
  it('meets everything a built-in theme must: every token, legal pairs, readable text, visible ring', () => {
    expect(themeProblems(bbsRevival)).toEqual([])
  })

  it('is amber on near-black', () => {
    // Hue 70 to 90 is amber; lightness under 0.2 is near-black.
    for (const key of ['foreground', 'primary', 'ring']) {
      const hue = Number(/oklch\([\d.]+ [\d.]+ ([\d.]+)\)/.exec(bbsRevival[key] ?? '')?.[1])
      expect(hue, key).toBeGreaterThanOrEqual(70)
      expect(hue, key).toBeLessThanOrEqual(90)
    }
    expect(Number(/oklch\(([\d.]+)/.exec(bbsRevival['background'] ?? '')?.[1])).toBeLessThan(0.2)
  })

  it('is monospace throughout: the sans and heading fonts are the mono stack', () => {
    expect(bbsRevival['font-sans']).toBe(bbsRevival['font-mono'])
    expect(bbsRevival['font-mono']).toMatch(/monospace$/)
    expect(bbsRevival['font-heading']).toBe('var(--ubb-font-sans)')
  })

  it('draws box rules: a double border thick enough to show, with single 1px lines elsewhere', () => {
    expect(bbsRevival['border-style']).toBe('double')
    expect(parseFloat(bbsRevival['border-width-strong'] ?? '0')).toBeGreaterThanOrEqual(3)
    expect(bbsRevival['border-width']).toBe('1px')
  })

  it('is dense and square: a smaller spacing unit, no rounding, and zero shadows (never "none")', () => {
    expect(parseFloat(bbsRevival['spacing'] ?? '1')).toBeLessThan(0.25)
    for (const k of ['radius-sm', 'radius-md', 'radius-lg', 'radius-xl'])
      expect(bbsRevival[k], k).toBe('0')
    for (const k of ['shadow-xs', 'shadow-sm', 'shadow-md', 'shadow-lg']) {
      expect(bbsRevival[k], k).toBe('0 0 0 0 transparent')
    }
  })

  it('keeps control borders at 3:1 against the ground, where Refined Terminal only reaches 1.6', () => {
    expect(
      contrastRatio(bbsRevival['border'] ?? '', bbsRevival['background'] ?? ''),
    ).toBeGreaterThanOrEqual(3)
    expect(
      contrastRatio(bbsRevival['input'] ?? '', bbsRevival['background'] ?? ''),
    ).toBeGreaterThanOrEqual(3)
  })
})
