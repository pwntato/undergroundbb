import { describe, expect, it } from 'vitest'
import { unreadAriaLabel, unreadLabel } from './unreadLabel'

describe('unreadLabel', () => {
  it('shows nothing for none, or when the server sent no count', () => {
    expect(unreadLabel(0, false)).toBeNull()
    expect(unreadLabel(undefined, undefined)).toBeNull()
  })
  it('shows the number', () => {
    expect(unreadLabel(3, false)).toBe('3')
    expect(unreadLabel(99, false)).toBe('99')
  })
  it('shows a plus when the count is a lower bound', () => {
    expect(unreadLabel(99, true)).toBe('99+')
    expect(unreadLabel(12, true)).toBe('12+')
  })
  it('never shows a badge for zero, even when the count is a lower bound', () => {
    expect(unreadLabel(0, true)).toBeNull()
  })
})

describe('unreadAriaLabel', () => {
  it('is singular for one', () => {
    expect(unreadAriaLabel('1')).toBe('1 unread notification')
    expect(unreadAriaLabel('2')).toBe('2 unread notifications')
    expect(unreadAriaLabel('99+')).toBe('99+ unread notifications')
    expect(unreadAriaLabel('1+')).toBe('1+ unread notifications')
  })
})
