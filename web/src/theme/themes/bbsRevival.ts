import type { Theme } from '../tokens'

/**
 * BBS Revival (#50): amber phosphor on near-black, monospace throughout, box-drawing rules and dense
 * rows. The ancestor of the name, kept to restraint: the density is meant to feel fast, so there is
 * no glow, no scanlines, no blinking, and headings stay in sentence case.
 *
 * How the token vocabulary says each part of that:
 * - amber on near-black: the colors; `primary` is inverse video (near-black on amber), as a BBS menu bar.
 * - monospace throughout: `font-sans` and `font-heading` are the mono stack too.
 * - box-drawing rules: `border-style: double` with a 3px strong border. A double rule only draws at
 *   3px and up, so ordinary 1px borders (inputs, dividers) stay single lines and the cards and alerts
 *   get the double-line box.
 * - dense rows: a smaller spacing unit, which every padding, margin, gap and height multiplies.
 * - no rounding and no shadow: radii are zero; shadows are the zero shadow, never `none`, because the
 *   focus ring shares one box-shadow list with them and `none` would void the whole list.
 */
export const bbsRevival: Theme = {
  background: 'oklch(0.14 0.012 75)',
  foreground: 'oklch(0.82 0.15 78)',
  muted: 'oklch(0.22 0.025 75)',
  'muted-foreground': 'oklch(0.7 0.11 75)',
  surface: 'oklch(0.18 0.02 75)',
  'surface-foreground': 'oklch(0.82 0.15 78)',
  card: 'oklch(0.18 0.02 75)',
  'card-foreground': 'oklch(0.82 0.15 78)',
  border: 'oklch(0.5 0.1 75)',
  input: 'oklch(0.5 0.1 75)',
  ring: 'oklch(0.88 0.15 85)',
  primary: 'oklch(0.82 0.16 78)',
  'primary-foreground': 'oklch(0.14 0.012 75)',
  accent: 'oklch(0.3 0.06 75)',
  'accent-foreground': 'oklch(0.9 0.13 82)',
  secondary: 'oklch(0.24 0.035 75)',
  'secondary-foreground': 'oklch(0.82 0.15 78)',
  destructive: 'oklch(0.7 0.19 28)',
  'destructive-foreground': 'oklch(0.14 0.012 75)',

  'font-sans': "ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, Consolas, monospace",
  'font-mono': "ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, Consolas, monospace",
  'font-heading': 'var(--ubb-font-sans)',

  'radius-sm': '0',
  'radius-md': '0',
  'radius-lg': '0',
  'radius-xl': '0',

  'border-width': '1px',
  'border-width-strong': '3px',
  'border-style': 'double',

  'shadow-xs': '0 0 0 0 transparent',
  'shadow-sm': '0 0 0 0 transparent',
  'shadow-md': '0 0 0 0 transparent',
  'shadow-lg': '0 0 0 0 transparent',

  spacing: '0.2rem',

  'case-heading': 'none',
  'tracking-heading': '0em',
  'tracking-body': '0em',
}
