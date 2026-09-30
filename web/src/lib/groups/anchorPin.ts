// Trust-on-first-use pin of a group's chain anchor (creator uuid + Ed25519
// key) -- issue #55. The first time this browser sees a group's anchor and
// its root grant verifies, the anchor is remembered here; later the served
// anchor must match, so a server that swaps in an invented creator after
// that first sight is caught (grant-chain.ts's pinnedAnchor).
//
// localStorage, not sessionStorage, and deliberately NOT cleared on logout:
// the pin is only worth anything if it outlives the session, and a logout
// that forgot it would hand a malicious server a fresh first sight. Keyed by
// the signed-in user id so accounts sharing a browser never share pins.
//
// First-contact limit: a server that lies on the very first sight is
// pinned. This is not the signed PIN# rows DESIGN.md describes for user key
// sets (not built); it only covers the anchor.

const STORAGE_KEY_PREFIX = 'undergroundbb:anchorPin:'

export interface StoredAnchorPin {
  readonly creatorUserId: string
  readonly creatorSigningPublicKey: string
}

/** The two Storage methods this module needs, so tests can inject a fake. */
export interface PinStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

function defaultStorage(): PinStorage | null {
  try {
    return localStorage
  } catch {
    return null
  }
}

function keyFor(userId: string, groupId: string): string {
  return `${STORAGE_KEY_PREFIX}${userId}:${groupId}`
}

/**
 * Reads the pin for (userId, groupId). Null for missing, corrupt or
 * unreadable storage: a pin that cannot be read is treated as never taken.
 */
export function readAnchorPin(
  userId: string,
  groupId: string,
  storage: PinStorage | null = defaultStorage(),
): StoredAnchorPin | null {
  try {
    const raw = storage?.getItem(keyFor(userId, groupId)) ?? null
    if (raw === null) {
      return null
    }
    const parsed: unknown = JSON.parse(raw)
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'creatorUserId' in parsed &&
      typeof parsed.creatorUserId === 'string' &&
      'creatorSigningPublicKey' in parsed &&
      typeof parsed.creatorSigningPublicKey === 'string'
    ) {
      return {
        creatorUserId: parsed.creatorUserId,
        creatorSigningPublicKey: parsed.creatorSigningPublicKey,
      }
    }
    return null
  } catch {
    return null
  }
}

/** Stores the pin. False when storage is missing or refused the write. */
export function writeAnchorPin(
  userId: string,
  groupId: string,
  pin: StoredAnchorPin,
  storage: PinStorage | null = defaultStorage(),
): boolean {
  try {
    if (storage === null) {
      return false
    }
    storage.setItem(
      keyFor(userId, groupId),
      JSON.stringify({
        creatorUserId: pin.creatorUserId,
        creatorSigningPublicKey: pin.creatorSigningPublicKey,
      }),
    )
    return true
  } catch {
    return false
  }
}
