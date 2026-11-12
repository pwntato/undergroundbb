// The session's hold on theme sync (#366): which account is signed in, a queue so changes are sent one
// at a time in order, and a way for the Appearance screen to hear that a login sync changed the page.
// The rules themselves are in theme/themeSync.ts.

import { getPreferences, putPreferences } from '@/lib/api/preferences'
import { openPreferencesBlob, sealPreferencesText } from '@/lib/crypto/worker-client'
import { browserStore } from '@/theme/applyTheme'
import {
  markPrefsDirty,
  pushLocal,
  syncAtLogin,
  type SyncOutcome,
  type ThemeSyncDeps,
} from '@/theme/themeSync'

let userId: string | null = null
/** The login sync while it runs: a change made meanwhile must neither lose to it nor race its send. */
let loginSync: Promise<unknown> | null = null
let sending = false
let again = false
const listeners = new Set<() => void>()

function depsFor(id: string): ThemeSyncDeps {
  return {
    userId: id,
    target: document.documentElement,
    store: browserStore(),
    read: getPreferences,
    write: putPreferences,
    seal: (text) => sealPreferencesText(id, text),
    open: (blob) => openPreferencesBlob(id, blob),
  }
}

/** Run when the page's theme was changed by a sync, so an open screen can read it again. */
export function onThemeSynced(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

/**
 * A session restored without a login (a reload, a new tab): the keys are not live, so a change cannot be
 * sealed, but it must still be flagged for the next login rather than silently left to lose to the blob.
 */
export function attachThemeSync(id: string): void {
  userId = id
}

/** After login, with the worker's keys live: let the blob and this browser settle on one choice. */
export async function startThemeSync(id: string): Promise<SyncOutcome> {
  userId = id
  const running = syncAtLogin(depsFor(id))
  loginSync = running
  let outcome: SyncOutcome
  try {
    outcome = await running
  } finally {
    if (loginSync === running) loginSync = null
  }
  if (userId === id && (outcome === 'applied' || outcome === 'pushed')) {
    for (const l of listeners) l()
  }
  return outcome
}

/** Logout (or a lost session): later changes stay in this browser only. */
export function stopThemeSync(): void {
  userId = null
}

/** The page's theme or custom themes changed here: send the new state. Changes made in a burst are coalesced. */
export function notifyThemeChanged(): void {
  if (userId === null) return
  // Mid login sync: flag the change now so the merge keeps it; it is sent once the sync is done.
  if (loginSync !== null) markPrefsDirty(browserStore(), userId)
  if (sending) {
    again = true
    return
  }
  sending = true
  void (async () => {
    try {
      do {
        again = false
        // Never race the login sync's own send: wait for it, then send what it left.
        if (loginSync !== null) await loginSync.catch(() => undefined)
        const id = userId
        if (id === null) return
        await pushLocal(depsFor(id))
      } while (again)
    } finally {
      sending = false
    }
  })()
}
