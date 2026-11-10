// Pulled into its own module (not GroupList.tsx, which oxlint's
// react/only-export-components rule wants to export nothing but the
// component itself, for fast-refresh's sake) and not runListGroups.ts
// (that file is about fetching/decrypting data, not display strings).

import { memberLabel } from './memberLabel'
import type { DisplayGroup } from './runListGroups'

/**
 * The label to show for one group -- covers every DisplayGroup.nameStatus,
 * including the direct-message case and the two failure states (issue #35's own "one bad entry must
 * not blank the whole list" requirement): 'unreadable' shows a fallback
 * rather than an empty string, and 'coldKeys' shows a placeholder distinct
 * from a genuinely unreadable group, since re-authenticating is what fixes
 * this one (GroupList's own enter-your-password hint covers the how) -- see
 * #143 (hasLiveKeys pre-check), which would let this distinguish "cold"
 * from "corrupt" even before a decrypt is attempted.
 */
export function groupLabel(group: DisplayGroup, usernames?: ReadonlyMap<string, string>): string {
  switch (group.nameStatus) {
    case 'dm':
      // A DM has no name (#73): it is called by the other person's username, or a plain word
      // where that has not been read (or the entry came without it).
      return group.dmWith === undefined ? 'Direct message' : memberLabel(group.dmWith, usernames)
    case 'plaintext':
    case 'decrypted':
      return group.displayName ?? '(unnamed group)'
    case 'unreadable':
      return '(unreadable group)'
    case 'coldKeys':
      return '(private group)'
  }
}
