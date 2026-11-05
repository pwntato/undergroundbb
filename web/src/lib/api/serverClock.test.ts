import { beforeEach, describe, expect, it } from 'vitest'
import { forgetServerClock, noteServerDate, serverNowMs } from './serverClock'

const res = (headers: Record<string, string>) => ({
  headers: { get: (name: string) => headers[name.toLowerCase()] ?? null },
})
const DEVICE = Date.parse('2026-11-05T00:30:00Z')

describe('server clock', () => {
  beforeEach(forgetServerClock)

  it('knows nothing before any answer', () => {
    expect(serverNowMs(DEVICE)).toBeUndefined()
  })

  it('reads the offset from the Date header and applies it to any device time', () => {
    // The device is one hour behind the server.
    noteServerDate(res({ date: 'Thu, 05 Nov 2026 01:30:00 GMT' }), DEVICE)
    expect(serverNowMs(DEVICE)).toBe(DEVICE + 3_600_000)
    expect(serverNowMs(DEVICE + 5_000)).toBe(DEVICE + 3_600_000 + 5_000)
  })

  it('keeps the latest reading, so a corrected device clock is picked up', () => {
    noteServerDate(res({ date: 'Thu, 05 Nov 2026 01:30:00 GMT' }), DEVICE)
    noteServerDate(res({ date: 'Thu, 05 Nov 2026 00:30:00 GMT' }), DEVICE)
    expect(serverNowMs(DEVICE)).toBe(DEVICE)
  })

  it('ignores a cached answer, a missing header and an unreadable one', () => {
    noteServerDate(res({ date: 'Thu, 05 Nov 2026 00:30:00 GMT' }), DEVICE)
    noteServerDate(res({ date: 'Thu, 05 Nov 2026 09:00:00 GMT', age: '30' }), DEVICE)
    noteServerDate(res({}), DEVICE)
    noteServerDate(res({ date: 'not a date' }), DEVICE)
    expect(serverNowMs(DEVICE)).toBe(DEVICE)
  })

  it('does not throw for a response with no headers at all', () => {
    expect(() => {
      noteServerDate({} as never, DEVICE)
    }).not.toThrow()
  })
})
