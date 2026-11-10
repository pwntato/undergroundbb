import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * The heading tokens live in `@layer base`, so any utility on the element beats them. A heading
 * with `tracking-tight` or `font-mono` would ignore the theme's heading font and letter-spacing
 * (and `uppercase` would fight `case-heading`). So headings must not carry those utilities.
 */
const SRC = join(__dirname, '..')
const FORBIDDEN =
  /\b(tracking-[a-z]+|font-(sans|mono|heading)|uppercase|lowercase|capitalize|normal-case)\b/

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules') continue
    const path = join(dir, name)
    if (statSync(path).isDirectory()) out.push(...sourceFiles(path))
    else if (/\.tsx$/.test(name) && !/\.test\./.test(name) && !/testkit/.test(name)) out.push(path)
  }
  return out
}

/** Every `<h1>` to `<h4>` opening tag, and the title components' own class lists. */
function headingTags(source: string): string[] {
  const tags = source.match(/<h[1-4]\b[^>]*>/g) ?? []
  const slots = source.match(/data-slot="(?:card|alert)-title"[\s\S]{0,240}?\{\.\.\.props\}/g) ?? []
  return [...tags, ...slots]
}

describe('headings leave font, case and letter-spacing to the theme', () => {
  const files = sourceFiles(SRC)

  it('finds the headings it is meant to check', () => {
    const all = files.flatMap((f) => headingTags(readFileSync(f, 'utf8')))
    expect(all.length).toBeGreaterThan(40)
    expect(all.some((t) => t.includes('alert-title'))).toBe(true)
    expect(all.some((t) => t.includes('card-title'))).toBe(true)
  })

  it('has no tracking, font-family or case utility on any heading', () => {
    const bad: string[] = []
    for (const f of files) {
      for (const tag of headingTags(readFileSync(f, 'utf8'))) {
        if (FORBIDDEN.test(tag)) bad.push(`${f.slice(SRC.length)}: ${tag.slice(0, 80)}`)
      }
    }
    expect(bad).toEqual([])
  })
})
