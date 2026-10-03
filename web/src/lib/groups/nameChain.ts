// Fetches the GENKEY# links a private group's name needs. A name is sealed
// under the generation the group had when it was last written, and rotation
// does not re-encrypt it (docs/DESIGN.md, "Revocation mode"), so a member whose
// own key is newer needs the links between the two to walk back to it. The
// crypto worker does no network I/O, so the callers fetch the links here and
// hand them over.

import type { KeychainLink, KeychainResponse } from '@/lib/api/groups'

/** More pages than any real chain needs; stops a server that never ends. */
const MAX_PAGES = 100

/**
 * The links for generations nameGeneration..generation-1, or undefined when
 * they could not be fetched or do not cover the range (a missing link is a
 * gap, and a name behind a gap is unreadable rather than guessed at).
 * Returns an empty list when no walk is needed. Never throws: an unreadable
 * name is a per-group degradation, and a failed fetch is not cached as one.
 */
export async function fetchNameChain(
  getKeychain: (groupId: string, from: number, to: number) => Promise<KeychainResponse>,
  groupId: string,
  nameGeneration: number,
  generation: number,
): Promise<readonly KeychainLink[] | undefined> {
  if (nameGeneration >= generation) {
    return []
  }
  const to = generation - 1
  const links = new Map<number, KeychainLink>()
  try {
    let from = nameGeneration
    for (let page = 0; page < MAX_PAGES; page++) {
      const res = await getKeychain(groupId, from, to)
      for (const link of res.links) {
        if (link.generation >= nameGeneration && link.generation <= to) {
          links.set(link.generation, link)
        }
      }
      if (res.nextFrom === undefined) {
        break
      }
      if (res.nextFrom <= from) {
        return undefined // not advancing: a broken server, not a chain
      }
      from = res.nextFrom
    }
  } catch {
    return undefined
  }
  for (let g = nameGeneration; g <= to; g++) {
    if (!links.has(g)) {
      return undefined
    }
  }
  return [...links.values()]
}
