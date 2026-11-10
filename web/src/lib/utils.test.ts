import { describe, expect, it } from 'vitest'
import { cn } from './utils'

describe('cn with the theme border utilities', () => {
  it('keeps border-strong when a caller adds a border colour', () => {
    expect(cn('rounded-xl border-strong bg-card', 'border-destructive')).toBe(
      'rounded-xl border-strong bg-card border-destructive',
    )
  })

  it('lets a caller replace the width: border, border-0 and border-2 each win over border-strong', () => {
    for (const w of ['border', 'border-0', 'border-2']) {
      expect(cn('border-strong', w), w).toBe(w)
    }
  })

  it('lets border-strong replace an earlier width', () => {
    expect(cn('border', 'border-strong')).toBe('border-strong')
  })
})
