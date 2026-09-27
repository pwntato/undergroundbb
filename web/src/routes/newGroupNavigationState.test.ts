import { describe, expect, it } from 'vitest'
import type { GroupListEntry } from '@/lib/api/groups'
import { NEW_GROUP_STATE_KEY, readNewGroupState } from './newGroupNavigationState'

const VALID_ENTRY: GroupListEntry = {
  groupId: 'group-1',
  visibility: 'public',
  role: 'admin',
  generation: 0,
  namePlaintext: 'Book Club',
}

describe('readNewGroupState', () => {
  it('returns the entry when state carries a well-formed one under the key', () => {
    expect(readNewGroupState({ [NEW_GROUP_STATE_KEY]: VALID_ENTRY })).toEqual(VALID_ENTRY)
  })

  it('returns undefined for undefined/null state', () => {
    expect(readNewGroupState(undefined)).toBeUndefined()
    expect(readNewGroupState(null)).toBeUndefined()
  })

  it('returns undefined when the key is absent', () => {
    expect(readNewGroupState({ someOtherKey: 'value' })).toBeUndefined()
  })

  it('returns undefined for a primitive state (a route that sets its own unrelated state)', () => {
    expect(readNewGroupState('some string state')).toBeUndefined()
    expect(readNewGroupState(42)).toBeUndefined()
  })

  it('returns undefined when the value under the key is missing required GroupListEntry fields', () => {
    expect(readNewGroupState({ [NEW_GROUP_STATE_KEY]: { groupId: 'group-1' } })).toBeUndefined()
    expect(readNewGroupState({ [NEW_GROUP_STATE_KEY]: null })).toBeUndefined()
    expect(readNewGroupState({ [NEW_GROUP_STATE_KEY]: 'not an object' })).toBeUndefined()
  })
})
