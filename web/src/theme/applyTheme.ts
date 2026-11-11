import { DEFAULT_THEME, findTheme, type BuiltInTheme } from './themes'

/** The two things a theme is applied to: the `<html>` element, or a stand-in for it in a test. */
export interface ThemeTarget {
  readonly style: { setProperty(name: string, value: string): void }
  setAttribute(name: string, value: string): void
}

/** The part of `localStorage` used here, so a test can pass a Map-backed one or one that throws. */
export interface ThemeStore {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

/** The attribute on `<html>` that says which theme is on the page now, beside `data-theme` (its mode). */
export const THEME_ID_ATTRIBUTE = 'data-theme-id'

/** Where the chosen theme is kept in this browser (before login there is no profile to read). */
export const THEME_STORAGE_KEY = 'ubb.theme'

/**
 * Switch the page to a theme: every token as a custom property, and `data-theme` to the theme's mode.
 * Both are set through the CSSOM (`style.setProperty`), never by writing CSS text, and nothing
 * reloads, so the change shows at once. Every token is written, so switching away from a theme
 * leaves nothing of it behind.
 */
export function applyTheme(theme: BuiltInTheme, target: ThemeTarget): void {
  for (const [name, value] of Object.entries(theme.tokens)) {
    target.style.setProperty(`--ubb-${name}`, value)
  }
  target.setAttribute('data-theme', theme.mode)
  target.setAttribute(THEME_ID_ATTRIBUTE, theme.id)
}

/**
 * The id of the theme on the page now, read from the page itself and not from storage: with storage
 * blocked a switch still works but is not remembered, and a picker must still mark what is showing.
 * Before anything has been applied (the markup alone) the page is the default theme.
 */
export function appliedThemeId(root: { getAttribute(name: string): string | null }): string {
  return findTheme(root.getAttribute(THEME_ID_ATTRIBUTE))?.id ?? DEFAULT_THEME.id
}

/**
 * What a picker does when a card is pressed: switch to it and return the new current id, or leave
 * everything alone and return the old one if the id is not a built-in theme.
 */
export function pickTheme(
  id: string,
  currentId: string,
  target: ThemeTarget,
  store: ThemeStore | null,
): string {
  return switchTheme(id, target, store) ? id : currentId
}

/** The theme saved in this browser, or the default if there is none, it is unknown, or storage fails. */
export function storedTheme(store: ThemeStore | null): BuiltInTheme {
  try {
    return findTheme(store?.getItem(THEME_STORAGE_KEY)) ?? DEFAULT_THEME
  } catch {
    return DEFAULT_THEME
  }
}

/** Remember a choice. Best effort: blocked storage must not stop the switch itself. */
export function saveThemeId(id: string, store: ThemeStore | null): boolean {
  if (findTheme(id) === undefined) return false
  try {
    store?.setItem(THEME_STORAGE_KEY, id)
    return store !== null
  } catch {
    return false
  }
}

/** Apply a built-in theme now and remember it. An unknown id changes nothing and returns false. */
export function switchTheme(id: string, target: ThemeTarget, store: ThemeStore | null): boolean {
  const theme = findTheme(id)
  if (theme === undefined) return false
  applyTheme(theme, target)
  saveThemeId(id, store)
  return true
}

/** Put the theme saved in this browser on the page (the default if none): what runs at startup. */
export function applyStoredTheme(target: ThemeTarget, store: ThemeStore | null): BuiltInTheme {
  const theme = storedTheme(store)
  applyTheme(theme, target)
  return theme
}

/** The browser's `localStorage`, or null where even touching it throws (blocked site data). */
export function browserStore(): ThemeStore | null {
  try {
    return window.localStorage
  } catch {
    return null
  }
}
