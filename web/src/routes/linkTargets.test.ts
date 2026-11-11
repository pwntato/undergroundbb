import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * WCAG 2.5.8: a standalone link has to be at least 24px tall to press. A one-line `text-sm` link is
 * 20px, so every router link whose class list sets a small text size and draws an underline carries a
 * rem floor (`min-h-[1.5rem]`, a rem and not a spacing utility so a dense theme cannot shrink it).
 * Links inside a sentence are exempt and do not use these classes.
 */
const DIR = __dirname
const files = readdirSync(DIR).filter((f) => /\.tsx$/.test(f) && !/\.test\./.test(f))

describe('standalone link tap targets', () => {
  it('finds the links it is meant to check', () => {
    let count = 0
    for (const f of files)
      count += (readFileSync(join(DIR, f), 'utf8').match(/<Link\b/g) ?? []).length
    expect(count).toBeGreaterThan(20)
  })

  it('gives every small underlined <Link> a 24px floor and centres its text', () => {
    const bad: string[] = []
    for (const f of files) {
      const src = readFileSync(join(DIR, f), 'utf8')
      for (const tag of src.match(/<Link\b[\s\S]*?[^=]>/g) ?? []) {
        const cls = /className="([^"]*)"/.exec(tag)?.[1] ?? ''
        if (!/\btext-(sm|xs)\b/.test(cls) || !/underline/.test(cls)) continue
        if (
          !/min-h-\[1\.5rem\]/.test(cls) ||
          !/\bitems-center\b/.test(cls) ||
          !/\binline-flex\b/.test(cls)
        )
          bad.push(`${f}: ${tag.slice(0, 80)}`)
      }
    }
    expect(bad).toEqual([])
  })
})
