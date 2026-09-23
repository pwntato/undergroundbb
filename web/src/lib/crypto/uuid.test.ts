import { describe, expect, it } from 'vitest'
import { generateUserID, isValidUserID } from './uuid.js'

describe('generateUserID', () => {
  it('produces a well-formed lowercase RFC 4122 v4 uuid', () => {
    const id = generateUserID()
    expect(isValidUserID(id)).toBe(true)
  })

  it('is unique across many calls', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 1000; i++) {
      const id = generateUserID()
      expect(seen.has(id)).toBe(false)
      seen.add(id)
    }
  })
})

describe('isValidUserID', () => {
  it('rejects malformed input', () => {
    // Same cases as internal/idgen/idgen_test.go's TestValidUUIDRejectsMalformed.
    const cases = [
      '',
      'F47AC10B-58CC-4372-A567-0E02B2C3D479',
      'f47ac10b-58cc-1372-a567-0e02b2c3d479',
      'f47ac10b-58cc-4372-1567-0e02b2c3d479',
      'f47ac10b58cc4372a5670e02b2c3d479',
      'f47ac10b-58cc-4372-a567-0e02b2c3d47',
      'f47ac10b-58cc-4372-a567-0e02b2c3d4799',
      'g47ac10b-58cc-4372-a567-0e02b2c3d479',
      'f47ac10b-58cc-4372-a567-0e02b2c3d479 ',
      '../../etc/passwd',
    ]
    for (const id of cases) {
      expect(isValidUserID(id)).toBe(false)
    }
  })

  it('accepts a known-good example', () => {
    expect(isValidUserID('f47ac10b-58cc-4372-a567-0e02b2c3d479')).toBe(true)
  })
})
