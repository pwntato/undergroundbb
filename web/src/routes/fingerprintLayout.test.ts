import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * A fingerprint is read aloud and compared whole (#65), so it must be laid out by FingerprintBlock
 * (rows of four groups), never as one run of text the browser may break inside a group of digits
 * (#381). This scans the screens for a fingerprint value put straight into an element, whatever
 * its classes; the count below is a backstop for the screens known to show one.
 */
const FILES = readdirSync(__dirname).filter(
  (f) => f.endsWith('.tsx') && !f.endsWith('.test.tsx') && f !== 'FingerprintBlock.tsx',
)

describe('fingerprints are laid out by FingerprintBlock', () => {
  for (const file of FILES) {
    it(`${file} does not print a fingerprint as free text`, () => {
      const src = readFileSync(join(__dirname, file), 'utf8')
      // A fingerprint value printed straight into an element: `>{x.fingerprint}<`. Whatever the
      // element's classes, only FingerprintBlock may lay one out.
      const bad = src.match(/>\s*\{\s*[\w.?!]*[Ff]ingerprint\s*\}\s*</g)
      expect(bad).toBeNull()
    })
  }

  it('the screens that show a fingerprint use the block', () => {
    const users: [string, number][] = [
      ['CreateInviteScreen.tsx', 1],
      ['AcceptInviteScreen.tsx', 1],
      ['DormantMembersNotice.tsx', 1],
      ['GroupMembersPanel.tsx', 3],
    ]
    for (const [file, n] of users) {
      const src = readFileSync(join(__dirname, file), 'utf8')
      expect(src.match(/<FingerprintBlock\b/g)?.length ?? 0, file).toBe(n)
    }
  })
})
