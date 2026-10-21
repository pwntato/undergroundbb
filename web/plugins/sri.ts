import { createHash } from 'node:crypto'
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import type { Plugin } from 'vite'

// Subresource integrity for the tags Vite writes into index.html (#67). The browser refuses a
// script or stylesheet whose bytes differ from the hash, which narrows (does not close) the
// modified-JavaScript gap in docs/THREAT_MODEL.md: it catches a tampered file in the bucket or
// on the CDN, not a tampered index.html, which carries the hashes.
//
// It covers only tags in index.html. The crypto worker is inlined into the main bundle
// (`?worker&inline`, #248), so the bundle's hash covers it.

const TAG = /<(?:script|link)\b[^>]*?(?:src|href)="(\/assets\/[^"]+)"[^>]*>/g

export function integrityOf(bytes: string | Uint8Array): string {
  return `sha384-${createHash('sha384').update(bytes).digest('base64')}`
}

/**
 * Adds `integrity` to every /assets/ script and stylesheet tag. Throws when a tag points at a
 * file that is not in `files`, or when there is no such tag at all: a build that silently
 * emitted no hashes would look identical to one that worked.
 */
export function addIntegrity(
  html: string,
  files: ReadonlyMap<string, string | Uint8Array>,
): string {
  let count = 0
  const out = html.replace(TAG, (tag, path: string) => {
    const bytes = files.get(path.slice(1))
    if (bytes === undefined)
      throw new Error(`sri: ${path} is referenced by index.html but not in the bundle`)
    if (/\sintegrity=/.test(tag)) throw new Error(`sri: ${path} already has an integrity attribute`)
    count++
    return tag.replace(/\s*\/?>$/, (end) => ` integrity="${integrityOf(bytes)}"${end}`)
  })
  if (count === 0) throw new Error('sri: no /assets/ script or stylesheet tags found in index.html')
  return out
}

/**
 * Throws when an emitted .js file is not one index.html hashes. The crypto worker is inlined
 * into the main bundle (#248) so that nothing is fetched without a hash; a lazy import, a code
 * split or a dropped `&inline` would emit an untagged chunk that loads silently, so fail the
 * build instead. (Do not follow Vite's chunk-size advice to code-split: see
 * build.chunkSizeWarningLimit in vite.config.ts.)
 */
export function assertAllScriptsTagged(
  emitted: Iterable<string>,
  tagged: ReadonlySet<string>,
): void {
  for (const name of emitted)
    if (name.endsWith('.js') && !tagged.has(name))
      throw new Error(`sri: ${name} is emitted but not covered by an integrity tag`)
}

// Runs in writeBundle, on the files as they are on disk. The chunk code visible to
// transformIndexHtml is not the final output (the JS bundle's hash computed there did not match
// the written file, and the browser blocked an untampered app), so hash what is actually served.
export function subresourceIntegrity(): Plugin {
  return {
    name: 'underground-sri',
    apply: 'build',
    writeBundle: {
      order: 'post',
      handler(options) {
        const dir = options.dir
        if (dir === undefined) throw new Error('sri: build has no output directory')
        const indexPath = join(dir, 'index.html')
        const html = readFileSync(indexPath, 'utf8')
        const files = new Map<string, Uint8Array>()
        for (const [, path] of html.matchAll(TAG)) {
          if (path === undefined) continue
          const name = path.slice(1)
          if (existsSync(join(dir, name))) files.set(name, readFileSync(join(dir, name)))
        }
        writeFileSync(indexPath, addIntegrity(html, files))
        const assets = join(dir, 'assets')
        if (existsSync(assets)) {
          assertAllScriptsTagged(
            readdirSync(assets).map((f) => `assets/${f}`),
            new Set(files.keys()),
          )
        }
      },
    },
  }
}
