// Resolves user ids to usernames through GET /api/users/:id, for the roster
// and invite rows. Best effort: a failed read leaves that id out of the map
// and memberLabel falls back to the short id. Results are cached for the page
// lifetime; a username never changes, so nothing here expires. The one thing
// that does change is deletion: an id resolved earlier keeps its name until a
// reload, so do not rely on this cache to notice that an account was deleted.

import { useEffect, useState } from 'react'
import { getUser } from '@/lib/api/users'

const cache = new Map<string, string>()

/** Reads in flight at once; a large roster must not fire one request per member in a burst. */
export const MAX_CONCURRENT_READS = 8

/** Reads and caches every id not already known; returns the ids it resolved. Never throws. */
export async function resolveUsernames(
  ids: readonly string[],
  fetchUser: typeof getUser = getUser,
): Promise<ReadonlyMap<string, string>> {
  const wanted = [...new Set(ids)].filter((id) => !cache.has(id))
  let next = 0
  const worker = async () => {
    while (next < wanted.length) {
      const id = wanted[next++] as string
      try {
        const projection = await fetchUser(id)
        // A deleted account is cached as '' (memberLabel shows it as deleted), not
        // left unresolved, so its short id is not retried on every render.
        cache.set(id, projection.deleted === true ? '' : projection.username)
      } catch {
        // Leave it unresolved; the label falls back to the short id.
      }
    }
  }
  await Promise.all(Array.from({ length: Math.min(MAX_CONCURRENT_READS, wanted.length) }, worker))
  return new Map(
    ids.flatMap((id) => (cache.has(id) ? [[id, cache.get(id) as string] as const] : [])),
  )
}

export function clearUsernameCache(): void {
  cache.clear()
}

/** Usernames for `ids`, empty until the reads land. `ids` is compared by content. */
export function useUsernames(ids: readonly string[]): ReadonlyMap<string, string> {
  const [usernames, setUsernames] = useState<ReadonlyMap<string, string>>(new Map())
  const key = [...new Set(ids)].sort().join(',')
  useEffect(() => {
    if (key === '') {
      return
    }
    let cancelled = false
    void (async () => {
      const resolved = await resolveUsernames(key.split(','))
      if (!cancelled) {
        setUsernames(resolved)
      }
    })()
    return () => {
      cancelled = true
    }
  }, [key])
  return usernames
}
