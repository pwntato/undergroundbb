import { describe, expect, it } from 'vitest'
import { BUILT_IN_THEMES, findTheme } from '@/theme/themes'
import { themePreviewStyles } from './themePreview'

const theme = (id: string) => findTheme(id)!

describe('themePreviewStyles', () => {
  it('draws each theme from its own tokens: ground, ink, border, radius and shadow', () => {
    for (const t of BUILT_IN_THEMES) {
      const s = themePreviewStyles(t)
      expect(s.frame.background, t.id).toBe(t.tokens['background'])
      expect(s.frame.color, t.id).toBe(t.tokens['foreground'])
      expect(s.frame.border, t.id).toBe(
        `${t.tokens['border-width-strong']} ${t.tokens['border-style']} ${t.tokens['border']}`,
      )
      expect(s.frame.borderRadius, t.id).toBe(t.tokens['radius-lg'])
      expect(s.frame.boxShadow, t.id).toBe(t.tokens['shadow-md'])
      expect(s.button.background, t.id).toBe(t.tokens['primary'])
      expect(s.button.color, t.id).toBe(t.tokens['primary-foreground'])
    }
  })

  it('shows Zine as light, square, shadowed and uppercase, and BBS Revival as double-ruled and dense', () => {
    const zine = themePreviewStyles(theme('zine'))
    expect(zine.frame.borderRadius).toBe('0')
    expect(zine.frame.boxShadow).toMatch(/^\d+px \d+px 0 0 /)
    expect(zine.heading.textTransform).toBe('uppercase')
    expect(zine.heading.letterSpacing).toBe('0.04em')
    const bbs = themePreviewStyles(theme('bbs-revival'))
    expect(String(bbs.frame.border)).toContain('double')
    expect(String(bbs.frame.padding)).toContain('0.2rem')
    expect(String(themePreviewStyles(theme('refined-terminal')).frame.padding)).toContain('0.25rem')
  })

  it('resolves a heading font that points at the sans font, so the sample never shows a bare var()', () => {
    for (const t of BUILT_IN_THEMES) {
      const s = themePreviewStyles(t)
      expect(String(s.heading.fontFamily), t.id).not.toContain('var(')
      expect(String(s.frame.fontFamily), t.id).not.toContain('var(')
    }
    expect(themePreviewStyles(theme('refined-terminal')).heading.fontFamily).toBe(
      theme('refined-terminal').tokens['font-sans'],
    )
    expect(themePreviewStyles(theme('zine')).heading.fontFamily).toBe(
      theme('zine').tokens['font-heading'],
    )
  })

  it('uses no web fonts or urls, which the CSP would refuse', () => {
    for (const t of BUILT_IN_THEMES)
      expect(JSON.stringify(themePreviewStyles(t)), t.id).not.toMatch(/url\(/)
  })
})
