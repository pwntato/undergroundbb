import { describe, expect, it } from 'vitest'
import type { LoadState } from './GroupList'
import { failedFrom, loadingFrom } from './useGroupsLoad'

const ready: LoadState = { status: 'ready', groups: [] }

describe('refetch keeps the list on screen', () => {
  it('a fetch starting over a ready list leaves it, over anything else shows loading', () => {
    expect(loadingFrom(ready)).toBe(ready)
    expect(loadingFrom({ status: 'error' })).toEqual({ status: 'loading' })
    expect(loadingFrom({ status: 'loading' })).toEqual({ status: 'loading' })
  })
  it('a failed fetch over a ready list leaves it, otherwise it is the error', () => {
    expect(failedFrom(ready)).toBe(ready)
    expect(failedFrom({ status: 'loading' })).toEqual({ status: 'error' })
  })
})
