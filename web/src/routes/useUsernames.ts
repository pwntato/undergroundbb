// Resolves user ids to usernames through POST /api/users:batch, for the roster
// and invite rows: one request per hundred ids, not one per id. Best effort: an
// id the server does not return (unknown, or in a request that failed) is left
// out of the map and memberLabel falls back to the short id. Results are cached
// for the page lifetime; a username never changes, so nothing here expires. The
// one thing that does change is deletion: an id resolved earlier keeps its name
// until a reload, so do not rely on this cache to notice that an account was
// deleted.

import { useEffect, useState } from 'react'
import { getUsers } from '@/lib/api/users'

const cache = new Map<string, string>()

/** Reads and caches every id not already known; returns the ids it resolved. Never throws. */
export async function resolveUsernames(
  ids: readonly string[],
  fetchUsers: typeof getUsers = getUsers,
): Promise<ReadonlyMap<string, string>> {
  const wanted = [...new Set(ids)].filter((id) => !cache.has(id))
  if (wanted.length > 0) {
    try {
      for (const [id, projection] of await fetchUsers(wanted)) {
        // A deleted account is cached as '' (memberLabel shows it as deleted), not
        // left unresolved, so its short id is not retried on every render.
        cache.set(id, projection.deleted === true ? '' : projection.username)
      }
    } catch {
      // Leave them unresolved; the labels fall back to the short id.
    }
  }
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
