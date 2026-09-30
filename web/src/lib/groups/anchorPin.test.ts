import { describe, expect, it } from 'vitest'
import { readAnchorPin, writeAnchorPin, type PinStorage } from './anchorPin'

function fakeStorage(): PinStorage & { data: Map<string, string> } {
  const data = new Map<string, string>()
  return {
    data,
    getItem: (k) => data.get(k) ?? null,
    setItem: (k, v) => {
      data.set(k, v)
    },
  }
}

const PIN = { creatorUserId: 'creator-1', creatorSigningPublicKey: 'a2V5' }

describe('anchorPin', () => {
  it('round-trips a pin', () => {
    const s = fakeStorage()
    expect(writeAnchorPin('u1', 'g1', PIN, s)).toBe(true)
    expect(readAnchorPin('u1', 'g1', s)).toEqual(PIN)
  })

  it('scopes pins to the signed-in user and the group', () => {
    const s = fakeStorage()
    writeAnchorPin('u1', 'g1', PIN, s)
    expect(readAnchorPin('u2', 'g1', s)).toBeNull()
    expect(readAnchorPin('u1', 'g2', s)).toBeNull()
  })

  it('reads corrupt or wrong-shaped entries as no pin instead of throwing', () => {
    const s = fakeStorage()
    s.data.set('undergroundbb:anchorPin:u1:g1', '{not json')
    expect(readAnchorPin('u1', 'g1', s)).toBeNull()
    s.data.set('undergroundbb:anchorPin:u1:g1', JSON.stringify({ creatorUserId: 5 }))
    expect(readAnchorPin('u1', 'g1', s)).toBeNull()
    s.data.set('undergroundbb:anchorPin:u1:g1', 'null')
    expect(readAnchorPin('u1', 'g1', s)).toBeNull()
  })

  it('reports a failed write, and tolerates missing or throwing storage', () => {
    const throwing: PinStorage = {
      getItem: () => {
        throw new Error('blocked')
      },
      setItem: () => {
        throw new Error('quota')
      },
    }
    expect(writeAnchorPin('u1', 'g1', PIN, throwing)).toBe(false)
    expect(readAnchorPin('u1', 'g1', throwing)).toBeNull()
    expect(writeAnchorPin('u1', 'g1', PIN, null)).toBe(false)
    expect(readAnchorPin('u1', 'g1', null)).toBeNull()
  })
})
