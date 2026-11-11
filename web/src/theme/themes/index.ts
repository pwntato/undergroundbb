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
}

/** Every built-in theme, in the order a picker lists them. The first is the default. */
export const BUILT_IN_THEMES: readonly BuiltInTheme[] = [
  { id: 'refined-terminal', name: 'Refined Terminal', mode: 'dark', tokens: refinedTerminal },
  { id: 'bbs-revival', name: 'BBS Revival', mode: 'dark', tokens: bbsRevival },
  { id: 'zine', name: 'Zine', mode: 'light', tokens: zine },
]

export const DEFAULT_THEME: BuiltInTheme = BUILT_IN_THEMES[0] as BuiltInTheme

export function findTheme(id: string | null | undefined): BuiltInTheme | undefined {
  return BUILT_IN_THEMES.find((t) => t.id === id)
}
