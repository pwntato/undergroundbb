import { describe, expect, it } from 'vitest'
import { generateRecoveryCode, normalizeRecoveryCode } from './recovery-code.js'

const CODE_PATTERN =
  /^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{6}$/

describe('generateRecoveryCode', () => {
  it('produces the 5-5-5-5-6 hyphenated shape', () => {
    const code = generateRecoveryCode()
    expect(code).toMatch(CODE_PATTERN)
    expect(code.replace(/-/g, '')).toHaveLength(26)
  })

  it('never emits an excluded letter (I, L, O, U)', () => {
    for (let i = 0; i < 200; i++) {
      const code = generateRecoveryCode()
      expect(code).not.toMatch(/[ILOU]/)
    }
  })

  it('is not deterministic', () => {
    const codes = new Set(Array.from({ length: 50 }, () => generateRecoveryCode()))
    expect(codes.size).toBe(50)
  })
})

describe('normalizeRecoveryCode', () => {
  it('strips hyphens and whitespace, uppercases', () => {
    expect(normalizeRecoveryCode('e1ap1-w4kgy-196y7-qzfww-rmmfrv')).toBe(
      'E1AP1W4KGY196Y7QZFWWRMMFRV',
    )
    expect(normalizeRecoveryCode('  e1ap1 w4kgy 196y7 qzfww rmmfrv  ')).toBe(
      'E1AP1W4KGY196Y7QZFWWRMMFRV',
    )
  })

  it('maps commonly-mistyped excluded letters back to their digits', () => {
    expect(normalizeRecoveryCode('I')).toBe('1')
    expect(normalizeRecoveryCode('L')).toBe('1')
    expect(normalizeRecoveryCode('O')).toBe('0')
    expect(normalizeRecoveryCode('ILO')).toBe('110')
  })

  it('round-trips a freshly generated code through normalization unchanged in content', () => {
    const code = generateRecoveryCode()
    const bare = code.replace(/-/g, '')
    expect(normalizeRecoveryCode(code)).toBe(bare)
  })
})
