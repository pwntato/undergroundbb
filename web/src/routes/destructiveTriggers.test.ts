import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * A button that STARTS a destructive action is `destructive-outline`; the solid `destructive` fill
 * belongs to the confirm step only. In Zine the one red makes a solid destructive button look like a
 * primary one, so the trigger must not wear it. This scans each screen for the button with the
 * given label and checks its variant.
 */
function variantOf(file: string, label: string): string | undefined {
  const src = readFileSync(join(__dirname, file), 'utf8')
  const blocks = src.match(/<Button\b[\s\S]*?<\/Button>/g) ?? []
  const block = blocks.find((b) =>
    new RegExp(`>\\s*${label}\\s*<|^\\s*${label}\\s*$|'${label}'`, 'm').test(b),
  )
  return block === undefined ? undefined : /variant="([^"]+)"/.exec(block)?.[1]
}

describe('destructive actions: trigger outlined, confirm solid', () => {
  const triggers: [string, string][] = [
    ['LeaveGroupPanel.tsx', 'Leave group'],
    ['DeleteAccountPanel.tsx', 'Delete my account'],
    ['GroupSettingsPanel.tsx', 'Convert to Open'],
    ['GroupMembersPanel.tsx', 'Remove'],
  ]
  for (const [file, label] of triggers) {
    it(`${file}: "${label}" is destructive-outline`, () => {
      expect(variantOf(file, label)).toBe('destructive-outline')
    })
  }

  it('the confirm buttons stay solid destructive', () => {
    expect(variantOf('DeleteAccountPanel.tsx', 'Yes, delete my account')).toBe('destructive')
    expect(variantOf('GroupSettingsPanel.tsx', 'Convert this group to Open')).toBe('destructive')
  })
})
