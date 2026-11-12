// Keeping the theme choice in the encrypted preferences blob (#366), with `localStorage` still the
// pre-login source. The dependencies (server calls, the worker's seal and open) are passed in so the
// rules below can be tested without a worker or a server.
//
// THE PRECEDENCE RULE
//   * At login, a blob that opens WINS: its theme choice goes on the page and into localStorage, so
//     the choice follows the person to another device. Custom themes are JOINED (the blob's first):
//     one made on this browser before it ever synced is not thrown away; the cost is that a theme
//     deleted on another device returns from a browser that still holds it, until it is removed there.
//   * No blob yet, or one that does not open (a keypair change that was not re-sealed, damage), or one
//     that is not a document this release reads as version 1: this browser's choice SEEDS it. A blob
//     from a NEWER version is left alone, never overwritten.
//   * One exception keeps a choice from being lost: a change made while signed in that could not be
//     sealed or sent (no live keys after a page reload, the network, a rotation in between) sets
//     `ubb.prefsDirty`. At the next login that browser's choice wins and is sent, then the flag clears.
//   * After login each change is sent as it is made, last writer wins (so a removal propagates).
//   * A browser can be shared. `ubb.prefsOwner` names the account whose state `ubb.theme` and
//     `ubb.customThemes` hold once any account has synced here, and the dirty flag is per account
//     (`ubb.prefsDirty.<id>`). Another account logging in finds a foreign owner: that state is WIPED
//     (and the default theme put on the page) before anything is read, so it is never joined into,
//     seeded into, or sent as the new account's blob. An unset owner is a browser that never synced
//     (including every browser from before this existed): the join and the seeding above are for it.
//   * A change made while the login sync is still running marks the flag at once, so the login merge
//     keeps it; the merge reads this browser's state AFTER its network calls, never before.
//
// Everything opened from the blob is validated again (preferences.ts) before it reaches the page.

import {
  applyTheme,
  saveThemeId,
  THEME_STORAGE_KEY,
  type ThemeStore,
  type ThemeTarget,
} from './applyTheme'
import { CUSTOM_THEMES_KEY, loadCustomThemes, replaceCustomThemes } from './customThemes'
import {
  decodePreferences,
  encodePreferences,
  mergePreferences,
  samePreferences,
  type Preferences,
} from './preferences'
import { DEFAULT_THEME, findTheme } from './themes'

/** Set while a change made signed in has not reached that account's blob. One per account. */
export const prefsDirtyKey = (userId: string): string => `ubb.prefsDirty.${userId}`
/** The account whose theme state this browser holds, once any account has synced here. */
export const PREFS_OWNER_KEY = 'ubb.prefsOwner'

export interface WireBlob {
  readonly nonce: string
  readonly ciphertext: string
}

export interface ThemeSyncDeps {
  /** The signed-in account. */
  readonly userId: string
  readonly target: ThemeTarget
  readonly store: ThemeStore | null
  readonly read: () => Promise<{ keyEpoch: number; preferencesBlob?: WireBlob }>
  readonly write: (keyEpoch: number, blob: WireBlob) => Promise<void>
  /** Seal text under the account's key; rejects if the keys are not live. */
  readonly seal: (text: string) => Promise<WireBlob>
  /** Open a blob; null if it does not open; rejects if the keys are not live. */
  readonly open: (blob: WireBlob) => Promise<string | null>
}

export type SyncOutcome =
  /** The blob's choice is on the page now (and storage). */
  | 'applied'
  /** This browser's choice was sent (seeded, repaired, or sent as a change). */
  | 'pushed'
  | 'unchanged'
  /** The blob is from a newer release: left alone. */
  | 'left-alone'
  /** Could not read or send; the change stays flagged for the next login. */
  | 'failed'

function getFlag(store: ThemeStore | null, userId: string): boolean {
  try {
    return store?.getItem(prefsDirtyKey(userId)) === '1'
  } catch {
    return false
  }
}

function setFlag(store: ThemeStore | null, userId: string, dirty: boolean): void {
  try {
    store?.setItem(prefsDirtyKey(userId), dirty ? '1' : '0')
  } catch {
    // Best effort: blocked storage cannot hold the flag, and nothing else depends on it.
  }
}

/** A change was made that has not reached the blob (also used while the login sync is still running). */
export function markPrefsDirty(store: ThemeStore | null, userId: string): void {
  setFlag(store, userId, true)
}

function getOwner(store: ThemeStore | null): string | null {
  try {
    return store?.getItem(PREFS_OWNER_KEY) ?? null
  } catch {
    return null
  }
}

/** True when the theme state in this browser belongs to a different account. */
function foreignOwner(deps: ThemeSyncDeps): boolean {
  const owner = getOwner(deps.store)
  return owner !== null && owner !== '' && owner !== deps.userId
}

/**
 * Make this account the owner of the browser's theme state. If it belonged to another account, that
 * state is wiped first (the saved themes, the choice and this account's own stale flag) and the default
 * theme goes on the page, so nothing of the other account is read, joined or sent as this one's.
 */
function takeOwnership(deps: ThemeSyncDeps): void {
  try {
    if (foreignOwner(deps)) {
      deps.store?.setItem(CUSTOM_THEMES_KEY, '[]')
      deps.store?.setItem(THEME_STORAGE_KEY, '')
      applyTheme(DEFAULT_THEME, deps.target)
      setFlag(deps.store, deps.userId, false)
    }
    deps.store?.setItem(PREFS_OWNER_KEY, deps.userId)
  } catch {
    // Blocked storage holds no other account's state to leak.
  }
}

/** This browser's choice and custom themes, read from storage (validated again by the loaders). */
export function localPreferences(store: ThemeStore | null): Preferences {
  const customs = loadCustomThemes(store)
  let id: string | null = null
  try {
    id = store?.getItem(THEME_STORAGE_KEY) ?? null
  } catch {
    id = null
  }
  return { themeId: findTheme(id, customs) === undefined ? null : id, customs }
}

function isEmpty(prefs: Preferences): boolean {
  return prefs.themeId === null && prefs.customs.length === 0
}

async function send(
  deps: ThemeSyncDeps,
  prefs: Preferences,
  keyEpoch: number,
): Promise<SyncOutcome> {
  try {
    await deps.write(keyEpoch, await deps.seal(encodePreferences(prefs)))
    setFlag(deps.store, deps.userId, false)
    return 'pushed'
  } catch {
    setFlag(deps.store, deps.userId, true)
    return 'failed'
  }
}

function putOnPage(prefs: Preferences, deps: ThemeSyncDeps): void {
  // Custom themes first: saveThemeId only keeps an id that names a stored theme.
  replaceCustomThemes(prefs.customs, deps.store)
  const theme = findTheme(prefs.themeId, prefs.customs)
  if (theme === undefined) return
  applyTheme(theme, deps.target)
  saveThemeId(theme.id, deps.store)
}

/** Run once after login, while the account's keys are live. Never throws. */
export async function syncAtLogin(deps: ThemeSyncDeps): Promise<SyncOutcome> {
  // Before anything is read: another account's state must not be this account's local state.
  takeOwnership(deps)
  try {
    const read = await deps.read()

    let remote: Preferences | null = null
    if (read.preferencesBlob !== undefined) {
      const text = await deps.open(read.preferencesBlob)
      if (text !== null) {
        const decoded = decodePreferences(text)
        if (decoded.ok) remote = decoded.prefs
        else if (decoded.reason === 'unsupported-version') return 'left-alone'
      }
    }

    // Read AFTER the network calls: a change made while they ran is in storage by now (and has
    // marked the flag), so the merge below keeps it instead of putting an older state on the page.
    const local = localPreferences(deps.store)
    const dirty = getFlag(deps.store, deps.userId)

    if (remote === null) {
      // Nothing usable on the server: this browser seeds it. An empty browser has nothing to seed.
      return isEmpty(local) ? 'unchanged' : await send(deps, local, read.keyEpoch)
    }
    const merged = mergePreferences(local, remote, dirty ? 'local' : 'remote')
    const changedHere = !samePreferences(merged, local)
    if (changedHere) putOnPage(merged, deps)
    if (!samePreferences(merged, remote) || dirty) {
      const sent = await send(deps, merged, read.keyEpoch)
      return sent === 'pushed' && changedHere ? 'applied' : sent
    }
    return changedHere ? 'applied' : 'unchanged'
  } catch {
    return 'failed'
  }
}

/** Send this browser's current choice after a change. Never throws; a failure flags it for next login. */
export async function pushLocal(deps: ThemeSyncDeps): Promise<SyncOutcome> {
  // State that belongs to another account is never sent as this one's.
  if (foreignOwner(deps)) return 'failed'
  takeOwnership(deps)
  try {
    const { keyEpoch } = await deps.read()
    return await send(deps, localPreferences(deps.store), keyEpoch)
  } catch {
    setFlag(deps.store, deps.userId, true)
    return 'failed'
  }
}
