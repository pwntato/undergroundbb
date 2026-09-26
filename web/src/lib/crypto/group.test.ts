// generateGrantSortKey isn't a vector-pinned encoding like
// trustAnchorPayload/roleGrantPayload (vectors.test.ts covers those) --
// it's fresh CSPRNG-backed generation, the client-side counterpart of
// idgen.DaySuffix (Go), so it gets its own focused unit tests instead.

import { describe, expect, it } from 'vitest'
import { generateGrantSortKey } from './group.js'

const SUBJECT_UUID = 'f47ac10b-58cc-4372-a567-0e02b2c3d479'

describe('generateGrantSortKey', () => {
  it('produces the GRANT#<uuid>#<YYYY-MM-DD>#<16 hex chars> shape', () => {
    const now = new Date('2026-09-25T12:00:00.000Z')
    const key = generateGrantSortKey(SUBJECT_UUID, now)
    expect(key).toMatch(/^GRANT#[0-9a-f-]{36}#\d{4}-\d{2}-\d{2}#[0-9a-f]{16}$/)
    expect(key.startsWith(`GRANT#${SUBJECT_UUID}#2026-09-25#`)).toBe(true)
  })

  it('uses the UTC calendar day, not local time', () => {
    // 2026-09-25 23:30 UTC-5 is 2026-09-26 04:30 UTC -- a day where the
    // local and UTC calendar days genuinely differ, the same edge case
    // idgen_test.go's TestDaySuffixUsesUTC exercises on the Go side.
    const now = new Date('2026-09-26T04:30:00.000Z')
    const key = generateGrantSortKey(SUBJECT_UUID, now)
    expect(key).toContain('#2026-09-26#')
  })

  it('generates a fresh random suffix on every call', () => {
    const now = new Date('2026-09-25T12:00:00.000Z')
    const seen = new Set<string>()
    for (let i = 0; i < 1000; i++) {
      const key = generateGrantSortKey(SUBJECT_UUID, now)
      expect(seen.has(key)).toBe(false)
      seen.add(key)
    }
  })
})
