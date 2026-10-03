// Client-side cache of decrypted private-group names/descriptions -- issue
// #35. docs/DESIGN.md is explicit this is required, not optional, for the
// group list's own cost accounting to hold: "Client-side caching of names
// and unwrapped generation keys is what makes that acceptable" (the
// acceptable cost being one GENKEY# chain walk per private group on every
// page load, absent a cache). Entries are keyed on the NAME's generation
// and ciphertext stamp, not the member's own generation. Rotation (#58)
// changes the member's generation but does not re-seal the name, so a
// cached name stays correct across a rotation and needs no invalidation;
// only a rename (new nonces, so a new stamp) or a truncation re-seal can
// change what a cached entry should say, and both change the stamp.
//
// sessionStorage, not localStorage: scoped to one tab's lifetime, matching
// the crypto worker's own liveKeys cache (worker.ts's own doc comment) --
// both are cleared on logout (clearGroupNameCache, called alongside
// clearLiveKeys from SessionContext.tsx) and neither is meant to survive
// past this tab closing. Keyed by userId so a worker instance/tab reused
// across a logout/login never mixes a previous account's decrypted names
// into a new one's list.

const STORAGE_KEY_PREFIX = 'undergroundbb:groupNameCache:'

interface CachedEntry {
  readonly generation: number
  /** See nameStamp: binds the entry to the exact ciphertext it was decrypted from. */
  readonly stamp?: string
  readonly name: string | null
  readonly description: string | null
}

type CacheShape = Record<string, CachedEntry>

/**
 * Identifies the exact name/description ciphertext an entry was decrypted
 * from: the two AES-GCM nonces, which are fresh for every encryption. A
 * settings edit does NOT change a group's nameGeneration, so the generation
 * alone cannot tell a cached name from one another admin has since replaced
 * (PR #151 review: a stale hit silently reverted that admin's rename). Any
 * edit re-seals under new nonces, so a stamp mismatch is a miss.
 */
export function nameStamp(
  nameCiphertext: { readonly nonce: string },
  descriptionCiphertext: { readonly nonce: string },
): string {
  return `${nameCiphertext.nonce}:${descriptionCiphertext.nonce}`
}

/**
 * Reads userId's cache. Returns an empty object on anything short of a
 * well-formed cache -- missing key, disabled/blocked storage (private
 * browsing, cleared site data), or corrupt JSON -- rather than throwing,
 * since this is a pure convenience layer: every caller must already be
 * prepared to decrypt a group it "should" have had cached, and a cold cache
 * is just the slow path, not an error.
 */
function readCache(userId: string): CacheShape {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY_PREFIX + userId)
    if (raw === null) {
      return {}
    }
    const parsed: unknown = JSON.parse(raw)
    if (typeof parsed !== 'object' || parsed === null) {
      return {}
    }
    return parsed as CacheShape
  } catch {
    return {}
  }
}

function writeCache(userId: string, cache: CacheShape): void {
  try {
    sessionStorage.setItem(STORAGE_KEY_PREFIX + userId, JSON.stringify(cache))
  } catch {
    // Storage full/blocked -- the cache is a pure optimization, so a failed
    // write just means the next read decrypts again. Nothing to recover.
  }
}

/**
 * Looks up a previously cached decrypt for (userId, groupId), returning
 * null on a cache miss, a stamp mismatch (the ciphertext has changed since),
 * OR a generation mismatch -- the latter is what a
 * future rotation (#78) will actually produce: a cached entry from before a
 * rotation is stale, not merely absent, and must not be served as if it
 * still matches the member's current generation.
 */
export function getCachedGroupName(
  userId: string,
  groupId: string,
  generation: number,
  stamp: string,
): { name: string | null; description: string | null } | null {
  const entry = readCache(userId)[groupId]
  if (!entry || entry.generation !== generation || entry.stamp !== stamp) {
    return null
  }
  return { name: entry.name, description: entry.description }
}

/** Stores a fresh decrypt (or a fresh null-fields failure) for (userId, groupId) at generation. */
export function setCachedGroupName(
  userId: string,
  groupId: string,
  generation: number,
  stamp: string,
  name: string | null,
  description: string | null,
): void {
  const cache = readCache(userId)
  cache[groupId] = { generation, stamp, name, description }
  writeCache(userId, cache)
}

/**
 * Clears userId's entire cache -- called alongside clearLiveKeys on logout
 * (SessionContext.tsx) so a worker instance/tab reused across a
 * logout/login in the same tab never shows a previous account's decrypted
 * group names before that account's own liveKeys are even live again.
 */
export function clearGroupNameCache(userId: string): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY_PREFIX + userId)
  } catch {
    // Same reasoning as writeCache's catch -- nothing to recover from a
    // blocked/disabled storage backend, and leaving a stale entry behind is
    // the same failure mode a getCachedGroupName generation-mismatch already
    // handles safely on the read side.
  }
}
