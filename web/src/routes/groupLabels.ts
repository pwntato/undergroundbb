// Labels for a list of groups on the screens that do not render GroupList (#73): a DM has no name, so
// each one is labelled by the other person's username, read here in one batch. Best effort: a name
// that cannot be read leaves the plain "Direct message" rather than an id fragment.

import { groupLabel } from './groupLabel'
import type { DisplayGroup } from './runListGroups'
import { resolveUsernames } from './useUsernames'

export async function groupLabelsOf(
  groups: readonly DisplayGroup[],
  resolve: typeof resolveUsernames = resolveUsernames,
): Promise<Map<string, string>> {
  const others = groups.flatMap((g) =>
    g.groupType === 'dm' && g.dmWith !== undefined ? [g.dmWith] : [],
  )
  const names = others.length === 0 ? new Map<string, string>() : await resolve(others)
  return new Map(
    groups.map((g) => [
      g.groupId,
      g.groupType === 'dm' && g.dmWith !== undefined && !names.has(g.dmWith)
        ? 'Direct message'
        : groupLabel(g, names),
    ]),
  )
}
