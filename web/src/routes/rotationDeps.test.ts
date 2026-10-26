import { describe, expect, it } from 'vitest'
import { makeAcceptDeps, makeRotationDeps, makeSelfRekeyDeps } from './rotationDeps'

// The factories are wiring, but a missing `ownKeyHistoryFailure` silently turns
// "could not load your key history" back into a misleading tamper message.
describe('rotation deps wiring', () => {
  it('gives every runner that checks the caller’s own pins the history failure reason', () => {
    expect(typeof makeRotationDeps('u').ownKeyHistoryFailure).toBe('function')
    expect(typeof makeAcceptDeps('u').ownKeyHistoryFailure).toBe('function')
    expect(typeof makeAcceptDeps('u').loadOwnKeyHistory).toBe('function')
  })

  it('gives the self re-key runner both the re-key and the Open-group self-wrap', () => {
    const deps = makeSelfRekeyDeps('u')
    for (const fn of [
      deps.selfRekey,
      deps.selfWrap,
      deps.selfWrapCrypto,
      deps.startSelfRekeyCrypto,
    ]) {
      expect(typeof fn).toBe('function')
    }
  })
})
