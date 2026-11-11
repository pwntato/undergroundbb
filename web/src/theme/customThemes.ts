// The custom themes kept in this browser (#74): a JSON list in localStorage. What is read back is
// NEVER trusted as already valid: each entry goes through validateCustomTheme again before it can be
// applied or listed, so a hand-edited or damaged value cannot put anything on the page that an
// import could not. Syncing them across devices is #366.
//
// An entry that no longer validates (a later release narrowed a range, renamed a token or added a
// contrast check) is NOT thrown away: it stays in storage, is reported by readSavedThemes with its
// reasons and its JSON so the person can fix it, and goes only when they discard it. The Appearance
// screen shows these.

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

/** A saved entry that no longer passes, with what is wrong and the JSON as it was stored. */
export interface InvalidSavedTheme {
  /** Stable for this text, so a discard can name it. */
  readonly id: string
  readonly name: string
  readonly errors: readonly string[]
  readonly json: string
}

export interface SavedThemes {
  readonly valid: readonly CustomTheme[]
  readonly invalid: readonly InvalidSavedTheme[]
}

function textHash(text: string): string {
  let h = 2166136261
  for (const ch of text) h = Math.imul(h ^ ch.codePointAt(0)!, 16777619) >>> 0
  return h.toString(36)
}

function readRaw(store: CustomThemeStore | null): unknown[] {
  try {
    const raw = store?.getItem(CUSTOM_THEMES_KEY)
    const list: unknown = raw == null ? [] : JSON.parse(raw)
    return Array.isArray(list) ? list.slice(0, MAX_CUSTOM_THEMES) : []
  } catch {
    return []
  }
}

/** Everything saved, split into the themes that pass now and the entries that do not. */
export function readSavedThemes(store: CustomThemeStore | null): SavedThemes {
  const valid: CustomTheme[] = []
  const invalid: InvalidSavedTheme[] = []
  for (const entry of readRaw(store)) {
    const json = JSON.stringify(entry, null, 2) ?? 'null'
    const result = validateCustomTheme(JSON.stringify(entry))
    if (result.ok && !valid.some((t) => t.id === result.theme.id)) {
      valid.push(result.theme)
    } else if (!result.ok) {
      const name =
        typeof entry === 'object' &&
        entry !== null &&
        typeof (entry as { name?: unknown }).name === 'string'
          ? (entry as { name: string }).name.slice(0, 40)
          : '(unnamed entry)'
      invalid.push({ id: `invalid-${textHash(json)}`, name, errors: result.errors, json })
    }
  }
  return { valid, invalid }
}

/** The saved custom themes that are valid now, or none if storage fails. */
export function loadCustomThemes(store: CustomThemeStore | null): CustomTheme[] {
  return [...readSavedThemes(store).valid]
}

function write(
  themes: readonly CustomTheme[],
  invalid: readonly InvalidSavedTheme[],
  store: CustomThemeStore | null,
): boolean {
  try {
    if (store === null) return false
    const list = [
      ...themes.map((t) => JSON.parse(exportThemeJson(t)) as unknown),
      ...invalid.map((i) => JSON.parse(i.json) as unknown),
    ]
    store.setItem(CUSTOM_THEMES_KEY, JSON.stringify(list))
    return true
  } catch {
    return false
  }
}

export type AddResult =
  | { readonly ok: true; readonly themes: readonly CustomTheme[]; readonly replaced: boolean }
  | { readonly ok: false; readonly error: string }

/**
 * Keep a theme. The same name replaces the saved one (`replaced` says so); a different one beyond
 * the limit is refused. Entries that no longer validate count toward the limit and are kept.
 */
export function addCustomTheme(theme: CustomTheme, store: CustomThemeStore | null): AddResult {
  const { valid, invalid } = readSavedThemes(store)
  const replaced = valid.some((t) => t.id === theme.id)
  if (!replaced && valid.length + invalid.length >= MAX_CUSTOM_THEMES) {
    return {
      ok: false,
      error: `You can keep ${MAX_CUSTOM_THEMES} custom themes. Remove one first.`,
    }
  }
  const next = replaced ? valid.map((t) => (t.id === theme.id ? theme : t)) : [...valid, theme]
  return write(next, invalid, store)
    ? { ok: true, themes: next, replaced }
    : { ok: false, error: 'This browser would not let the page save the theme.' }
}

/** Forget a theme. Returns the themes that remain; entries that do not validate are kept. */
export function removeCustomTheme(id: string, store: CustomThemeStore | null): CustomTheme[] {
  const { valid, invalid } = readSavedThemes(store)
  const next = valid.filter((t) => t.id !== id)
  write(next, invalid, store)
  return next
}

/** Throw away one entry that no longer validates. */
export function discardInvalidTheme(id: string, store: CustomThemeStore | null): void {
  const { valid, invalid } = readSavedThemes(store)
  write(
    valid,
    invalid.filter((i) => i.id !== id),
    store,
  )
}
