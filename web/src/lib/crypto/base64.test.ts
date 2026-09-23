import { describe, expect, it } from 'vitest'
import { base64ToBytes, bytesToBase64 } from './base64.js'

describe('base64 round trip', () => {
  it('round-trips arbitrary bytes, including 0x00 and 0xff', () => {
    const bytes = new Uint8Array([0, 1, 2, 254, 255, 128, 127])
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes)
  })

  it('round-trips empty input', () => {
    const bytes = new Uint8Array([])
    expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes)
  })

  it('round-trips 32 random bytes at every length modulus', () => {
    for (let len = 0; len < 8; len++) {
      const bytes = crypto.getRandomValues(new Uint8Array(len))
      expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes)
    }
  })

  it('produces standard padded base64, not URL-safe', () => {
    // 0xfb 0xff 0xff encodes to "+///" in standard base64 (URL-safe would be "-___").
    const b64 = bytesToBase64(new Uint8Array([0xfb, 0xff, 0xff]))
    expect(b64).toBe('+///')
  })
})
