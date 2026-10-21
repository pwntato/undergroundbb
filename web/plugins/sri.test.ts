import { createHash } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import { addIntegrity, assertAllScriptsTagged, integrityOf } from './sri.ts'

const html = `<head>
<script type="module" crossorigin src="/assets/index-A.js"></script>
<link rel="stylesheet" crossorigin href="/assets/index-B.css">
<link rel="icon" href="/favicon.svg" />
</head>`

const files = new Map<string, string | Uint8Array>([
  ['assets/index-A.js', 'console.log(1)'],
  ['assets/index-B.css', new TextEncoder().encode('body{}')],
])

describe('addIntegrity', () => {
  it('hashes each /assets/ tag with sha384 of its bytes', () => {
    const out = addIntegrity(html, files)
    const js = `sha384-${createHash('sha384').update('console.log(1)').digest('base64')}`
    const css = `sha384-${createHash('sha384').update('body{}').digest('base64')}`
    expect(out).toContain(`src="/assets/index-A.js" integrity="${js}"></script>`)
    expect(out).toContain(`href="/assets/index-B.css" integrity="${css}">`)
  })

  it('leaves tags outside /assets/ alone', () => {
    expect(addIntegrity(html, files)).toContain('<link rel="icon" href="/favicon.svg" />')
  })

  it('gives different content different hashes', () => {
    expect(integrityOf('a')).not.toBe(integrityOf('b'))
  })

  it('throws when a referenced file is missing from the bundle', () => {
    expect(() => addIntegrity(html, new Map([['assets/index-A.js', 'x']]))).toThrow(/index-B\.css/)
  })

  it('throws when no tag matches, so an empty result cannot pass for success', () => {
    expect(() => addIntegrity('<head></head>', files)).toThrow(/no \/assets\//)
  })

  it('throws on a tag that already has integrity', () => {
    const had = '<script src="/assets/index-A.js" integrity="sha384-x"></script>'
    expect(() => addIntegrity(had, files)).toThrow(/already has/)
  })
})

describe('assertAllScriptsTagged', () => {
  const tagged = new Set(['assets/index-A.js'])

  it('accepts the tagged script and non-script assets', () => {
    expect(() =>
      assertAllScriptsTagged(['assets/index-A.js', 'assets/index-B.css'], tagged),
    ).not.toThrow()
  })

  it('refuses an emitted script that no tag hashes', () => {
    expect(() =>
      assertAllScriptsTagged(['assets/index-A.js', 'assets/worker-C.js'], tagged),
    ).toThrow(/assets\/worker-C\.js is emitted but not covered/)
  })
})
