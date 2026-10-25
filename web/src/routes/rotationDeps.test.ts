import { describe, expect, it } from 'vitest'
import { makeAcceptDeps, makeRotationDeps } from './rotationDeps'

// The factories are wiring, but a missing `ownKeyHistoryFailure` silently turns
// "could not load your key history" back into a misleading tamper message.
describe('rotation deps wiring', () => {
  it('gives every runner that checks the caller’s own pins the history failure reason', () => {
    expect(typeof makeRotationDeps('u').ownKeyHistoryFailure).toBe('function')
    expect(typeof makeAcceptDeps('u').ownKeyHistoryFailure).toBe('function')
    expect(typeof makeAcceptDeps('u').loadOwnKeyHistory).toBe('function')
  })
})
