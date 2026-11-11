// The session's hold on theme sync (#366): which account is signed in, a queue so changes are sent one
// at a time in order, and a way for the Appearance screen to hear that a login sync changed the page.
// The rules themselves are in theme/themeSync.ts.

import { getPreferences, putPreferences } from '@/lib/api/preferences'
import { openPreferencesBlob, sealPreferencesText } from '@/lib/crypto/worker-client'
import { browserStore } from '@/theme/applyTheme'
import { pushLocal, syncAtLogin, type SyncOutcome, type ThemeSyncDeps } from '@/theme/themeSync'

let userId: string | null = null
let sending = false
let again = false
const listeners = new Set<() => void>()

function depsFor(id: string): ThemeSyncDeps {
  return {
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

/** After login, with the worker's keys live: let the blob and this browser settle on one choice. */
export async function startThemeSync(id: string): Promise<SyncOutcome> {
  userId = id
  const outcome = await syncAtLogin(depsFor(id))
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
  if (sending) {
    again = true
    return
  }
  sending = true
  void (async () => {
    try {
      do {
        again = false
        const id = userId
        if (id === null) return
        await pushLocal(depsFor(id))
      } while (again)
    } finally {
      sending = false
    }
  })()
}
