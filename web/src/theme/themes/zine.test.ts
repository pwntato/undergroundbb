import { describe, expect, it } from 'vitest'
import { contrastRatio } from '../contrast'
import { themeProblems } from '../themeChecks'
import { headingPairProblem } from '../tokens'
import { zine } from './zine'

const lightness = (key: string): number => Number(/oklch\(([\d.]+)/.exec(zine[key] ?? '')?.[1])

describe('Zine', () => {
  it('meets everything a built-in theme must: every token, legal pairs, readable text, visible ring', () => {
    expect(themeProblems(zine)).toEqual([])
  })

  it('is bone stock and photocopy black: a light ground with near-black ink', () => {
    expect(lightness('background')).toBeGreaterThan(0.9)
    expect(lightness('foreground')).toBeLessThan(0.2)
  })

  it('has one riso red: primary is red hued, and destructive is a red too', () => {
    for (const key of ['primary', 'destructive']) {
      const hue = Number(/oklch\([\d.]+ [\d.]+ ([\d.]+)\)/.exec(zine[key] ?? '')?.[1])
      expect(hue, key).toBeGreaterThanOrEqual(20)
      expect(hue, key).toBeLessThanOrEqual(35)
    }
  })

  it('is square with thick borders: zero radii and a strong border of 3px or more', () => {
    for (const k of ['radius-sm', 'radius-md', 'radius-lg', 'radius-xl'])
      expect(zine[k], k).toBe('0')
    expect(parseFloat(zine['border-width-strong'] ?? '0')).toBeGreaterThanOrEqual(3)
    expect(zine['border-style']).toBe('solid')
  })

  it('casts hard shadows: an offset on both axes, no blur, and growing with the size', () => {
    const offsets: number[] = []
    for (const k of ['shadow-xs', 'shadow-sm', 'shadow-md', 'shadow-lg']) {
      const m = /^(\d+)px (\d+)px 0 0 oklch\(/.exec(zine[k] ?? '')
      expect(m, k).not.toBeNull()
      expect(m?.[1], k).toBe(m?.[2])
      offsets.push(Number(m?.[1]))
    }
    expect(offsets.every((o, i) => o > 0 && (i === 0 || o > (offsets[i - 1] ?? 0)))).toBe(true)
  })

  it('shadows are the ink color, so they hold 3:1 against the page', () => {
    expect(contrastRatio(zine['border'] ?? '', zine['background'] ?? '')).toBeGreaterThanOrEqual(3)
    expect(zine['shadow-lg']).toContain(zine['border'])
  })

  it('uppercases headings with letter-spacing above zero, in a heavy face', () => {
    expect(zine['case-heading']).toBe('uppercase')
    expect(parseFloat(zine['tracking-heading'] ?? '0')).toBeGreaterThan(0)
    expect(headingPairProblem(zine)).toBeNull()
    expect(zine['font-heading']).toMatch(/^Impact,/)
    expect(zine['font-heading']).not.toBe('var(--ubb-font-sans)')
  })

  it('keeps the body at the normal spacing unit and untracked, so threads stay readable', () => {
    expect(zine['spacing']).toBe('0.25rem')
    expect(zine['tracking-body']).toBe('0em')
  })

  it('uses system fonts only (the CSP has no font-src)', () => {
    for (const k of ['font-sans', 'font-mono', 'font-heading'])
      expect(zine[k], k).not.toMatch(/url\(|@font-face/)
  })
})
