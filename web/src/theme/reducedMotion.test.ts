import { readFileSync, readdirSync, statSync } from 'node:fs'
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

  it('sits after the base layer, not inside it', () => {
    const at = css.indexOf('@media (prefers-reduced-motion: reduce)')
    expect(at).toBeGreaterThan(css.lastIndexOf('@layer base'))
    // Nothing nested: every brace opened before the block has been closed.
    const before = css.slice(0, at)
    expect((before.match(/\{/g) ?? []).length).toBe((before.match(/\}/g) ?? []).length)
  })

  it('no source file forces its own motion with an important utility, which would beat this block', () => {
    const bad: string[] = []
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const path = join(dir, name)
        if (statSync(path).isDirectory()) walk(path)
        else if (/\.(tsx?|css)$/.test(name) && !/\.test\./.test(name)) {
          const src = readFileSync(path, 'utf8')
          if (
            /!(duration|delay|transition|animate|ease)[-\w[\]]*/.test(src) ||
            /(^|[\s"'`])(duration|delay)-\[?\d[^\s"'`]*!/.test(src)
          )
            bad.push(path)
        }
      }
    }
    walk(join(__dirname, '..'))
    expect(bad).toEqual([])
  })
})
