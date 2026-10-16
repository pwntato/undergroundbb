import { createHash } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

import type { Plugin } from 'vite'

// Subresource integrity for the tags Vite writes into index.html (#67). The browser refuses a
// script or stylesheet whose bytes differ from the hash, which narrows (does not close) the
// modified-JavaScript gap in docs/THREAT_MODEL.md: it catches a tampered file in the bucket or
// on the CDN, not a tampered index.html, which carries the hashes.
//
// It covers only tags in index.html. The crypto worker (and anything it loads) is fetched at
// runtime by `new Worker(...)`, which has no integrity option, so it is not covered.

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
      },
    },
  }
}
