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
