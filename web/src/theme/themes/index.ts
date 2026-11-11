import type { Theme } from '../tokens'
import { bbsRevival } from './bbsRevival'
import { refinedTerminal } from './refinedTerminal'
import { zine } from './zine'

/**
 * `dark` or `light`: the value of `<html data-theme>`. The vendored components' `dark:` classes (and
 * the `dark` variant in index.css) key off `data-theme="dark"`, so a theme that is not dark has to
 * say so or those classes paint a dark fill onto a light page.
 */
export type ThemeMode = 'dark' | 'light'

export interface BuiltInTheme {
  readonly id: string
  readonly name: string
  readonly mode: ThemeMode
  readonly tokens: Theme
  /** Set on a theme the person imported (#74); never on a built-in. */
  readonly custom?: true
}

/** Every built-in theme, in the order a picker lists them. The first is the default. */
export const BUILT_IN_THEMES: readonly BuiltInTheme[] = [
  { id: 'refined-terminal', name: 'Refined Terminal', mode: 'dark', tokens: refinedTerminal },
  { id: 'bbs-revival', name: 'BBS Revival', mode: 'dark', tokens: bbsRevival },
  { id: 'zine', name: 'Zine', mode: 'light', tokens: zine },
]

export const DEFAULT_THEME: BuiltInTheme = BUILT_IN_THEMES[0] as BuiltInTheme

/** A built-in theme by id, or one of `custom` (the validated imports kept in this browser, #74). */
export function findTheme(
  id: string | null | undefined,
  custom: readonly BuiltInTheme[] = [],
): BuiltInTheme | undefined {
  return BUILT_IN_THEMES.find((t) => t.id === id) ?? custom.find((t) => t.id === id)
}
