// The Appearance screen's state and what each of its actions does to it (#53, #74), kept apart from
// the component so a test can run an import against a real store and page without a DOM: the screen
// only holds the state and passes these functions the page and the store.

import {
  MAX_THEME_TEXT,
  exportThemeJson,
  validateCustomTheme,
  type CustomTheme,
} from '@/theme/customTheme'
import {
  addCustomTheme,
  discardInvalidTheme,
  readSavedThemes,
  type InvalidSavedTheme,
} from '@/theme/customThemes'
import {
  appliedThemeId,
  forgetCustomTheme,
  switchTheme,
  type ThemeStore,
  type ThemeTarget,
} from '@/theme/applyTheme'
import { findTheme } from '@/theme/themes'

export interface AppearanceState {
  readonly currentId: string
  readonly customs: readonly CustomTheme[]
  /** What is in the import box. */
  readonly importText: string
  /** Saved entries that no longer pass the rules, kept so they can be read and fixed (#74 review). */
  readonly invalid: readonly InvalidSavedTheme[]
  /** A line about what the last import did beyond adding (it replaced a saved theme), or null. */
  readonly notice: string | null
  /** Why the last import was refused; empty when it was not. */
  readonly errors: readonly string[]
  /** The JSON of the theme on the page, once "Show as JSON" was pressed; null before. */
  readonly exportText: string | null
}

export interface AppearanceEnv {
  readonly target: ThemeTarget & { getAttribute(name: string): string | null }
  readonly store: ThemeStore | null
}

export function initialAppearance(env: AppearanceEnv): AppearanceState {
  const { valid: customs, invalid } = readSavedThemes(env.store)
  return {
    currentId: appliedThemeId(env.target, customs),
    customs,
    invalid,
    notice: null,
    importText: '',
    errors: [],
    exportText: null,
  }
}

export function typeImport(state: AppearanceState, text: string): AppearanceState {
  return { ...state, importText: text.slice(0, MAX_THEME_TEXT + 1) }
}

/** Validate what was pasted; if it is fine, keep it and put it on the page now. */
export function runImport(state: AppearanceState, env: AppearanceEnv): AppearanceState {
  const result = validateCustomTheme(state.importText)
  if (!result.ok) return { ...state, errors: result.errors }
  const added = addCustomTheme(result.theme, env.store)
  if (!added.ok) return { ...state, errors: [added.error] }
  switchTheme(result.theme.id, env.target, env.store)
  return {
    ...state,
    customs: added.themes,
    currentId: result.theme.id,
    notice: added.replaced ? `Replaced your saved theme "${result.theme.name}".` : null,
    importText: '',
    errors: [],
    exportText: null,
  }
}

/** Forget one custom theme; if it was showing, the default theme comes back. */
export function runRemove(state: AppearanceState, id: string, env: AppearanceEnv): AppearanceState {
  const currentId = forgetCustomTheme(id, state.currentId, env.target, env.store)
  const saved = readSavedThemes(env.store)
  return {
    ...state,
    currentId,
    customs: saved.valid,
    invalid: saved.invalid,
    notice: null,
    exportText: null,
  }
}

/** Throw away an entry that no longer validates. */
export function runDiscard(
  state: AppearanceState,
  id: string,
  env: AppearanceEnv,
): AppearanceState {
  discardInvalidTheme(id, env.store)
  return { ...state, invalid: readSavedThemes(env.store).invalid, notice: null }
}

/** The theme on the page as copyable JSON (a built-in is offered as a copy, under a new name). */
export function runExport(state: AppearanceState): AppearanceState {
  const theme = findTheme(state.currentId, state.customs)
  if (theme === undefined) return state
  const name = theme.custom === true ? theme.name : `${theme.name} copy`
  return { ...state, exportText: exportThemeJson({ ...theme, name }) }
}

/** A card was pressed. */
export function runSelect(state: AppearanceState, id: string, env: AppearanceEnv): AppearanceState {
  if (!switchTheme(id, env.target, env.store)) return state
  return { ...state, currentId: id, exportText: null }
}
