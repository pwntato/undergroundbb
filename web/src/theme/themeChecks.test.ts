import { describe, expect, it } from 'vitest'
import { themeProblems } from './themeChecks'
import { refinedTerminal } from './themes/refinedTerminal'

const with_ = (over: Record<string, string>) => ({ ...refinedTerminal, ...over })

describe('themeProblems', () => {
  it('finds nothing wrong with a good theme', () => {
    expect(themeProblems(refinedTerminal)).toEqual([])
  })

  it('names a missing and an unknown token', () => {
    const { ring: _ring, ...rest } = refinedTerminal
    expect(themeProblems(rest)).toEqual(['missing token ring'])
    expect(themeProblems(with_({ sparkle: '1' }))).toEqual(['unknown token sparkle'])
  })

  it('refuses unreadable text, naming the pair and the ratio', () => {
    const out = themeProblems(with_({ 'muted-foreground': 'oklch(0.3 0.016 255)' }))
    expect(out.some((p) => p.startsWith('muted-foreground on background'))).toBe(true)
  })

  it('refuses a ring that fades below 3:1 as the 50% halo even if solid it passes', () => {
    const out = themeProblems(with_({ ring: 'oklch(0.74 0.09 195)' }))
    expect(out.some((p) => p.startsWith('ring/50 on background'))).toBe(true)
    expect(out.some((p) => p.startsWith('ring on background'))).toBe(false)
  })

  it('refuses a bad border style, a bad case and an illegal heading pair', () => {
    expect(themeProblems(with_({ 'border-style': 'groove' }))).toEqual(['border-style groove'])
    expect(themeProblems(with_({ 'case-heading': 'shouting' }))).toEqual(['case-heading shouting'])
    expect(
      themeProblems(with_({ 'case-heading': 'uppercase', 'tracking-heading': '0em' })),
    ).toHaveLength(1)
  })
})
