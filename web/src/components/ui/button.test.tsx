import { describe, expect, it } from 'vitest'
import { buttonVariants } from './button'

describe('the destructive button', () => {
  const cls = buttonVariants({ variant: 'destructive' })

  it('uses the destructive-foreground token, the pair the theme tests hold to 4.5:1', () => {
    expect(cls).toContain('bg-destructive')
    expect(cls).toContain('text-destructive-foreground')
  })

  it('does not hard-code white or lean on the dark: variant for its background', () => {
    expect(cls).not.toContain('text-white')
    expect(cls).not.toContain('dark:bg-destructive')
  })
})

describe('the smallest buttons keep a 24px target at any spacing unit', () => {
  // h-6 and size-6 scale with the theme's spacing unit (BBS Revival's 0.2rem gives 19.2px); a rem
  // floor does not, so the target stays at least 24px (WCAG 2.2, 2.5.8) under every theme.
  it('has a rem floor on xs', () => {
    expect(buttonVariants({ size: 'xs' })).toContain('min-h-[1.5rem]')
  })

  it('has a rem floor on both sides of icon-xs', () => {
    const cls = buttonVariants({ size: 'icon-xs' })
    expect(cls).toContain('min-h-[1.5rem]')
    expect(cls).toContain('min-w-[1.5rem]')
  })
})
