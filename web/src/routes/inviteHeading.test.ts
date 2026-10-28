import { describe, expect, it } from 'vitest'
import { inviteHeading } from './inviteHeading'

describe('inviteHeading', () => {
  it('names a public group', () => {
    expect(inviteHeading('Book Club')).toBe("You've been invited to Book Club")
  })

  it('stays generic when the server sent no name', () => {
    expect(inviteHeading(undefined)).toBe("You've been invited")
  })
})
