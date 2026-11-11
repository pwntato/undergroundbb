// What goes in the encrypted preferences blob (#366) and how it is read back. The document is
// versioned JSON, `{ v: 1, theme?: string, customThemes?: object[] }`, sealed by the crypto worker.
//
// Everything opened from the blob is UNTRUSTED text, the same as a pasted import: it is parsed
// defensively, and each custom theme goes through validateCustomTheme again, so a blob written by a
// future or older release, a damaged one, or one a bug filled with junk cannot put anything on the
// page that an import could not. Nothing here writes to the page or to storage.

import {
  MAX_CUSTOM_THEMES,
  exportThemeJson,
  validateCustomTheme,
  type CustomTheme,
} from './customTheme'
import { findTheme } from './themes'

export const PREFERENCES_VERSION = 1
/** Longest theme id read from a blob (built-in ids are short; custom ones are slugs of a 40 char name). */
const MAX_THEME_ID = 80

export interface Preferences {
  /** The chosen theme's id, or null if the blob names none. */
  readonly themeId: string | null
  /** The custom themes that passed validation, at most MAX_CUSTOM_THEMES. */
  readonly customs: readonly CustomTheme[]
}

export type DecodedPreferences =
  | { readonly ok: true; readonly prefs: Preferences }
  /** Not a document this release can read (damaged, or a version it does not know). Do not overwrite it. */
  | { readonly ok: false; readonly reason: 'malformed' | 'unsupported-version' }

export function encodePreferences(prefs: Preferences): string {
  return JSON.stringify({
    v: PREFERENCES_VERSION,
    ...(prefs.themeId === null ? {} : { theme: prefs.themeId }),
    customThemes: prefs.customs
      .slice(0, MAX_CUSTOM_THEMES)
      .map((t) => JSON.parse(exportThemeJson(t)) as unknown),
  })
}

export function decodePreferences(text: string): DecodedPreferences {
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    return { ok: false, reason: 'malformed' }
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    return { ok: false, reason: 'malformed' }
  }
  const record = doc as { v?: unknown; theme?: unknown; customThemes?: unknown }
  if (record.v !== PREFERENCES_VERSION) {
    return { ok: false, reason: typeof record.v === 'number' ? 'unsupported-version' : 'malformed' }
  }
  const customs: CustomTheme[] = []
  const list: unknown = record.customThemes
  if (Array.isArray(list)) {
    for (const entry of list.slice(0, MAX_CUSTOM_THEMES)) {
      const result = validateCustomTheme(JSON.stringify(entry))
      if (result.ok && !customs.some((t) => t.id === result.theme.id)) customs.push(result.theme)
    }
  }
  const theme = record.theme
  const themeId =
    typeof theme === 'string' && theme.length > 0 && theme.length <= MAX_THEME_ID ? theme : null
  return { ok: true, prefs: { themeId, customs } }
}

/**
 * Combine this browser's preferences with the blob's. `winner` is whose theme choice and whose copy
 * of a same-named custom theme is kept; the custom theme LISTS are joined (the winner's first), so a
 * theme made on this device before login is not thrown away, capped at the limit.
 *
 * The chosen id is only kept if it names a theme that exists in the merged set; otherwise the other
 * side's choice is tried, and then null (the caller falls back to the default).
 */
export function mergePreferences(
  local: Preferences,
  remote: Preferences,
  winner: 'remote' | 'local',
): Preferences {
  const [first, second] = winner === 'remote' ? [remote, local] : [local, remote]
  const customs: CustomTheme[] = []
  for (const t of [...first.customs, ...second.customs]) {
    if (!customs.some((c) => c.id === t.id)) customs.push(t)
  }
  const kept = customs.slice(0, MAX_CUSTOM_THEMES)
  const themeId =
    [first.themeId, second.themeId].find(
      (id) => id !== null && findTheme(id, kept) !== undefined,
    ) ?? null
  return { themeId, customs: kept }
}

/** True when two preference sets would encode to the same document. */
export function samePreferences(a: Preferences, b: Preferences): boolean {
  return encodePreferences(a) === encodePreferences(b)
}
