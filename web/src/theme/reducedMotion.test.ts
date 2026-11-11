import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const css = readFileSync(join(__dirname, '..', 'index.css'), 'utf8')
const block = /@media \(prefers-reduced-motion: reduce\)\s*\{([\s\S]*?)\n\}/.exec(css)?.[1] ?? ''

describe('prefers-reduced-motion', () => {
  it('has a reduce block that covers every element and pseudo-element', () => {
    expect(block).not.toBe('')
    expect(block).toMatch(/\*,\s*::before,\s*::after/)
  })

  it('makes transitions and animations effectively instant, but not zero so end events still fire', () => {
    expect(block).toMatch(/transition-duration:\s*0\.01ms\s*!important/)
    expect(block).toMatch(/animation-duration:\s*0\.01ms\s*!important/)
    expect(block).toMatch(/animation-iteration-count:\s*1\s*!important/)
    expect(block).toMatch(/scroll-behavior:\s*auto\s*!important/)
  })

  it('is not wrapped in a layer a utility could beat (the rule is !important anyway)', () => {
    expect(css.indexOf('@media (prefers-reduced-motion: reduce)')).toBeGreaterThan(
      css.lastIndexOf('@layer base'),
    )
  })
})
