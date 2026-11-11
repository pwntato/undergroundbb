import type { Theme } from '../tokens'

/**
 * Zine (#51): bone stock, photocopy black, one riso red. The theme the token vocabulary was drawn up
 * against, so every part of it is a token and nothing needs a special case.
 *
 * How the vocabulary says each part:
 * - bone, black and one red: the colors. Ink is near-black with a warm tint, `primary` is the red,
 *   and a button is bone lettering on red. It is the one light built-in theme.
 * - hard offset shadows: real shadows with no blur and a solid ink color, never a soft one. The zero
 *   shadow is `0 0 0 0 transparent` where a theme wants none, never `none`; Zine uses real offsets.
 * - zero radius and thick borders: radii are 0 and the strong border is 3px ink, so cards and alerts
 *   read as cut paper. Control borders (1px) are ink too, so they hold 3:1 against the page.
 * - heavy uppercase headings: a condensed heavy system face, `case-heading: uppercase` with the
 *   letter-spacing above zero that a legal uppercase pair requires.
 * - body stays plain: a neutral sans at the normal spacing unit, because a threaded discussion has to
 *   stay readable at density. The costume is in the headings, borders and shadows, not the prose.
 *
 * No web fonts: the Content-Security-Policy has no `font-src`, so the stacks name fonts a system has.
 */
const ink = 'oklch(0.16 0.006 80)'

export const zine: Theme = {
  background: 'oklch(0.95 0.025 88)',
  foreground: ink,
  muted: 'oklch(0.89 0.03 86)',
  'muted-foreground': 'oklch(0.4 0.015 80)',
  surface: 'oklch(0.98 0.015 90)',
  'surface-foreground': ink,
  card: 'oklch(0.98 0.015 90)',
  'card-foreground': ink,
  border: ink,
  input: ink,
  ring: ink,
  primary: 'oklch(0.5 0.2 27)',
  'primary-foreground': 'oklch(0.97 0.015 90)',
  accent: 'oklch(0.86 0.06 88)',
  'accent-foreground': ink,
  secondary: 'oklch(0.9 0.03 86)',
  'secondary-foreground': ink,
  destructive: 'oklch(0.45 0.19 27)',
  'destructive-foreground': 'oklch(0.97 0.015 90)',

  'font-sans': "'Helvetica Neue', Helvetica, Arial, 'Liberation Sans', sans-serif",
  'font-mono': "ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, Consolas, monospace",
  'font-heading':
    "Impact, Haettenschweiler, 'Arial Narrow Bold', 'Helvetica Neue', Arial, sans-serif",

  'radius-sm': '0',
  'radius-md': '0',
  'radius-lg': '0',
  'radius-xl': '0',

  'border-width': '1px',
  'border-width-strong': '3px',
  'border-style': 'solid',

  'shadow-xs': `2px 2px 0 0 ${ink}`,
  'shadow-sm': `3px 3px 0 0 ${ink}`,
  'shadow-md': `5px 5px 0 0 ${ink}`,
  'shadow-lg': `8px 8px 0 0 ${ink}`,

  spacing: '0.25rem',

  'case-heading': 'uppercase',
  'tracking-heading': '0.04em',
  'tracking-body': '0em',
}
