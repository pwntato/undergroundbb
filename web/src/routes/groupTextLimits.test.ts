import { describe, expect, it } from 'vitest'
import { groupTextLengthError, utf8Length } from './groupTextLimits'

describe('utf8Length', () => {
  it('counts bytes, not UTF-16 units', () => {
    expect(utf8Length('abc')).toBe(3)
    expect(utf8Length('é')).toBe(2)
    expect(utf8Length('日')).toBe(3)
    expect(utf8Length('😀')).toBe(4)
  })
})

describe('groupTextLengthError', () => {
  it('accepts text exactly at the byte limits', () => {
    expect(groupTextLengthError('a'.repeat(200), 'a'.repeat(2000))).toBeNull()
    expect(groupTextLengthError('é'.repeat(100), 'é'.repeat(1000))).toBeNull()
    expect(groupTextLengthError('😀'.repeat(50), '😀'.repeat(500))).toBeNull()
  })

  it('rejects a name over 200 bytes, including ones under 200 characters', () => {
    expect(groupTextLengthError('a'.repeat(201), '')).toMatch(/^Group name is too long/)
    expect(groupTextLengthError('é'.repeat(101), '')).toMatch(/^Group name is too long/)
    expect(groupTextLengthError('日'.repeat(67), '')).toMatch(/^Group name is too long/)
    expect(groupTextLengthError('x'.repeat(199) + 'é', '')).toMatch(/^Group name is too long/)
  })

  it('rejects a description over 2000 bytes, including one under 2000 characters', () => {
    expect(groupTextLengthError('ok', 'a'.repeat(2001))).toMatch(/^Description is too long/)
    expect(groupTextLengthError('ok', 'é'.repeat(1001))).toMatch(/^Description is too long/)
  })

  it('reports the name first when both are over, and names the byte limit', () => {
    const err = groupTextLengthError('a'.repeat(201), 'a'.repeat(2001))
    expect(err).toMatch(/^Group name is too long/)
    expect(err).toContain('200 bytes')
    expect(groupTextLengthError('ok', 'a'.repeat(2001))).toContain('2000 bytes')
  })
})
