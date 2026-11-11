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
//
// Everything opened from the blob is validated again (preferences.ts) before it reaches the page.

import {
  applyTheme,
  saveThemeId,
  THEME_STORAGE_KEY,
  type ThemeStore,
  type ThemeTarget,
} from './applyTheme'
import { loadCustomThemes, replaceCustomThemes } from './customThemes'
import {
  decodePreferences,
  encodePreferences,
  mergePreferences,
  samePreferences,
  type Preferences,
} from './preferences'
import { findTheme } from './themes'

/** Set while a change made signed in has not reached the blob. */
export const PREFS_DIRTY_KEY = 'ubb.prefsDirty'

export interface WireBlob {
  readonly nonce: string
  readonly ciphertext: string
}

export interface ThemeSyncDeps {
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

function getFlag(store: ThemeStore | null): boolean {
  try {
    return store?.getItem(PREFS_DIRTY_KEY) === '1'
  } catch {
    return false
  }
}

function setFlag(store: ThemeStore | null, dirty: boolean): void {
  try {
    store?.setItem(PREFS_DIRTY_KEY, dirty ? '1' : '0')
  } catch {
    // Best effort: blocked storage cannot hold the flag, and nothing else depends on it.
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
    setFlag(deps.store, false)
    return 'pushed'
  } catch {
    setFlag(deps.store, true)
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
  try {
    const read = await deps.read()
    const local = localPreferences(deps.store)
    const dirty = getFlag(deps.store)

    let remote: Preferences | null = null
    if (read.preferencesBlob !== undefined) {
      const text = await deps.open(read.preferencesBlob)
      if (text !== null) {
        const decoded = decodePreferences(text)
        if (decoded.ok) remote = decoded.prefs
        else if (decoded.reason === 'unsupported-version') return 'left-alone'
      }
    }

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
  try {
    const { keyEpoch } = await deps.read()
    return await send(deps, localPreferences(deps.store), keyEpoch)
  } catch {
    setFlag(deps.store, true)
    return 'failed'
  }
}
