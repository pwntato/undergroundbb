// The custom themes kept in this browser (#74): a JSON list in localStorage. What is read back is
// NEVER trusted as already valid: each entry goes through validateCustomTheme again before it can be
// applied or listed, so a hand-edited or damaged value cannot put anything on the page that an
// import could not. Syncing them across devices is #366.

import {
  MAX_CUSTOM_THEMES,
  exportThemeJson,
  validateCustomTheme,
  type CustomTheme,
} from './customTheme'

export const CUSTOM_THEMES_KEY = 'ubb.customThemes'

export interface CustomThemeStore {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

/** The saved custom themes that are still valid, at most MAX_CUSTOM_THEMES, or none if storage fails. */
export function loadCustomThemes(store: CustomThemeStore | null): CustomTheme[] {
  let list: unknown
  try {
    const raw = store?.getItem(CUSTOM_THEMES_KEY)
    list = raw == null ? [] : JSON.parse(raw)
  } catch {
    return []
  }
  if (!Array.isArray(list)) return []
  const themes: CustomTheme[] = []
  for (const entry of list.slice(0, MAX_CUSTOM_THEMES)) {
    const result = validateCustomTheme(JSON.stringify(entry))
    if (result.ok && !themes.some((t) => t.id === result.theme.id)) themes.push(result.theme)
  }
  return themes
}

function write(themes: readonly CustomTheme[], store: CustomThemeStore | null): boolean {
  try {
    if (store === null) return false
    store.setItem(
      CUSTOM_THEMES_KEY,
      JSON.stringify(themes.map((t) => JSON.parse(exportThemeJson(t)))),
    )
    return true
  } catch {
    return false
  }
}

export type AddResult =
  | { readonly ok: true; readonly themes: readonly CustomTheme[] }
  | { readonly ok: false; readonly error: string }

/** Keep a theme. The same name replaces the saved one; a sixth different one is refused. */
export function addCustomTheme(theme: CustomTheme, store: CustomThemeStore | null): AddResult {
  const current = loadCustomThemes(store)
  const replaced = current.some((t) => t.id === theme.id)
  if (!replaced && current.length >= MAX_CUSTOM_THEMES) {
    return {
      ok: false,
      error: `You can keep ${MAX_CUSTOM_THEMES} custom themes. Remove one first.`,
    }
  }
  const next = replaced ? current.map((t) => (t.id === theme.id ? theme : t)) : [...current, theme]
  return write(next, store)
    ? { ok: true, themes: next }
    : { ok: false, error: 'This browser would not let the page save the theme.' }
}

/** Forget a theme. Returns the themes that remain. */
export function removeCustomTheme(id: string, store: CustomThemeStore | null): CustomTheme[] {
  const next = loadCustomThemes(store).filter((t) => t.id !== id)
  write(next, store)
  return next
}
