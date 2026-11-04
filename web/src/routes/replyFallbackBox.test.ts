import { describe, expect, it } from 'vitest'
import { fallbackBox } from './replyFallbackBox'

describe('fallbackBox', () => {
  it('cannot send while a reply target is kept but not on screen', () => {
    const box = fallbackBox({ replyTo: '0060', commentCount: 50 })
    expect(box.waiting).toBe(true)
    expect(box.label).not.toBe('Add a comment')
    expect(box.hint).toMatch(/once the comment shows/)
  })

  it('is the plain new-comment box with no target', () => {
    expect(fallbackBox({ replyTo: null, commentCount: 3 })).toEqual({
      label: 'Add a comment',
      hint: undefined,
      waiting: false,
    })
    expect(fallbackBox({ replyTo: null, commentCount: 0 }).label).toBe('Write the first comment')
  })
})
