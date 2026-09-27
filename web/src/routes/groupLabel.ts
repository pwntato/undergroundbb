// Pulled into its own module (not GroupList.tsx, which oxlint's
// react/only-export-components rule wants to export nothing but the
// component itself, for fast-refresh's sake) and not runListGroups.ts
// (that file is about fetching/decrypting data, not display strings).

import type { DisplayGroup } from './runListGroups'

/**
 * The label to show for one group -- covers every DisplayGroup.nameStatus,
 * including the two failure states (issue #35's own "one bad entry must
 * not blank the whole list" requirement): 'unreadable' shows a fallback
 * rather than an empty string, and 'coldKeys' shows a placeholder distinct
 * from a genuinely unreadable group, since re-authenticating is what fixes
 * this one (GroupList's own "log in again" hint covers the how) -- see
 * #143 (hasLiveKeys pre-check), which would let this distinguish "cold"
 * from "corrupt" even before a decrypt is attempted.
 */
export function groupLabel(group: DisplayGroup): string {
  switch (group.nameStatus) {
    case 'plaintext':
    case 'decrypted':
      return group.displayName ?? '(unnamed group)'
    case 'unreadable':
      return '(unreadable group)'
    case 'coldKeys':
      return '(private group)'
  }
}
