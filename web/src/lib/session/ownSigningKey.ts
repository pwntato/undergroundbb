// The signed-in user's own PUBLIC signing key, cached at login -- issue #63.
// The worker holds the real keys only in memory, so a full page reload drops
// them while the session cookie survives; without this the roster check could
// not tell whose key it was looking at and fell back to "unchecked" until the
// next login. A public key is not a secret, and the worker stays the
// authority: the cache is only a fallback for when it has no live keys.
//
// sessionStorage: it survives a reload but not a closed tab, matching the
// lifetime of the session it describes. Keyed by user id so a stale entry for
// another account is never returned.

const STORAGE_KEY_PREFIX = 'undergroundbb:ownSigningKey:'

/** The Storage methods this module needs, so tests can inject a fake. */
export interface KeyStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

function defaultStorage(): KeyStorage | null {
  try {
    return sessionStorage
  } catch {
    return null
  }
}

/** Best effort: a failed write just means a reload will need a re-login. */
export function cacheOwnSigningKey(
  userId: string,
  signingPublicKey: string,
  storage: KeyStorage | null = defaultStorage(),
): void {
  try {
    storage?.setItem(STORAGE_KEY_PREFIX + userId, signingPublicKey)
  } catch {
    // Storage full or refused.
  }
}

export function readCachedOwnSigningKey(
  userId: string,
  storage: KeyStorage | null = defaultStorage(),
): string | null {
  try {
    return storage?.getItem(STORAGE_KEY_PREFIX + userId) ?? null
  } catch {
    return null
  }
}

export function clearCachedOwnSigningKey(
  userId: string,
  storage: KeyStorage | null = defaultStorage(),
): void {
  try {
    storage?.removeItem(STORAGE_KEY_PREFIX + userId)
  } catch {
    // Nothing to do.
  }
}

/**
 * The worker's key if it has live keys, else the cached one, else rejects
 * with the worker's error (so the caller reports "unchecked").
 */
export async function ownSigningKeyWithFallback(
  userId: string,
  fromWorker: (userId: string) => Promise<string>,
  storage: KeyStorage | null = defaultStorage(),
): Promise<string> {
  try {
    return await fromWorker(userId)
  } catch (err) {
    const cached = readCachedOwnSigningKey(userId, storage)
    if (cached !== null) {
      return cached
    }
    throw err
  }
}
