import { describe, expect, it } from 'vitest'
import type { CreateGroupResult } from './runCreateGroup'
import { buildGroupListEntry } from './buildGroupListEntry'

const RESULT = {
  ok: true,
  groupKeyWrapped: { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' },
} as Extract<CreateGroupResult, { ok: true }>

const form = (over: Record<string, unknown>) =>
  ({ visibility: 'private', revocationMode: 'rotating', expirationDays: 0, ...over }) as never

// The entry Home shows before the list read catches up carries whether the
// group has a re-key, the same as the server's list does.
describe('buildGroupListEntry', () => {
  it.each([
    ['a private Rotating group', { visibility: 'private', revocationMode: 'rotating' }, false],
    ['a private Open group', { visibility: 'private', revocationMode: 'open' }, true],
    ['a public group', { visibility: 'public', revocationMode: 'open' }, true],
  ])('marks %s noRotation = %s', (_name, over, want) => {
    expect(buildGroupListEntry('g', form(over), RESULT).noRotation).toBe(want)
  })
})
