import { describe, expect, it } from 'vitest'
import { DELETED_USER_LABEL, memberLabel, unresolvedClass } from './memberLabel'

const ID = '0b30d94e-1111-4222-8333-444455556666'

describe('memberLabel', () => {
  it('shows the username once resolved', () => {
    expect(memberLabel(ID, new Map([[ID, 'alice']]))).toBe('alice')
  })

  it('falls back to the first block of the uuid while unresolved', () => {
    expect(memberLabel(ID, new Map())).toBe('0b30d94e')
    expect(memberLabel(ID)).toBe('0b30d94e')
  })

  it('calls an empty username a deleted user instead of rendering it blank', () => {
    expect(memberLabel(ID, new Map([[ID, '']]))).toBe(DELETED_USER_LABEL)
  })
})

describe('unresolvedClass', () => {
  it('is monospace only for the uuid-fragment fallback, not for a deleted user', () => {
    expect(unresolvedClass(ID, new Map())).toBe('font-mono')
    expect(unresolvedClass(ID, new Map([[ID, '']]))).toBe('')
  })
})
