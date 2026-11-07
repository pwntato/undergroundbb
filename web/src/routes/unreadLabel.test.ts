import { describe, expect, it } from 'vitest'
import { unreadLabel } from './unreadLabel'

describe('unreadLabel', () => {
  it('shows nothing for none', () => {
    expect(unreadLabel(0, false)).toBeNull()
  })
  it('shows the number', () => {
    expect(unreadLabel(3, false)).toBe('3')
    expect(unreadLabel(99, false)).toBe('99')
  })
  it('shows a plus when the count is a lower bound', () => {
    expect(unreadLabel(99, true)).toBe('99+')
    expect(unreadLabel(12, true)).toBe('12+')
    expect(unreadLabel(0, true)).toBe('0+')
  })
})
