import type { Theme } from '../tokens'

/**
 * Refined Terminal, the default theme (#49): a slate ground, a muted teal accent, prose in a
 * humanist sans, and monospace kept for data (keys, handles, counts, timestamps). Modern spacing
 * and softly rounded corners; the terminal heritage is in the palette and the mono, not in costume.
 *
 * These values are also the `:root` defaults in `src/index.css`, so the page is themed before any
 * script runs. `refinedTerminal.test.ts` fails if the two differ.
 *
 * No web fonts: the Content-Security-Policy sends `default-src 'none'` with no `font-src`, so the
 * stacks name fonts a system already has. The sans stack is the humanist one (Seravek on Apple,
 * Gill Sans Nova and Calibri on Windows, Ubuntu, DejaVu Sans elsewhere).
 */
export const refinedTerminal: Theme = {
  background: 'oklch(0.17 0.014 255)',
  foreground: 'oklch(0.93 0.008 255)',
  muted: 'oklch(0.25 0.014 255)',
  'muted-foreground': 'oklch(0.72 0.016 255)',
  surface: 'oklch(0.21 0.015 255)',
  'surface-foreground': 'oklch(0.93 0.008 255)',
  card: 'oklch(0.21 0.015 255)',
  'card-foreground': 'oklch(0.93 0.008 255)',
  border: 'oklch(0.34 0.016 255)',
  input: 'oklch(0.34 0.016 255)',
  // A touch lighter than primary: the focus halo is drawn at 50%, and needs 3:1 at that strength.
  ring: 'oklch(0.78 0.09 195)',
  primary: 'oklch(0.74 0.09 195)',
  'primary-foreground': 'oklch(0.17 0.014 255)',
  accent: 'oklch(0.29 0.022 215)',
  'accent-foreground': 'oklch(0.95 0.008 255)',
  secondary: 'oklch(0.27 0.016 255)',
  'secondary-foreground': 'oklch(0.93 0.008 255)',
  destructive: 'oklch(0.68 0.17 25)',
  'destructive-foreground': 'oklch(0.17 0.014 255)',

  'font-sans':
    "Seravek, 'Gill Sans Nova', Ubuntu, Calibri, 'DejaVu Sans', 'Source Sans 3', 'Source Sans Pro', sans-serif",
  'font-mono': "ui-monospace, 'SF Mono', 'JetBrains Mono', Menlo, Consolas, monospace",
  'font-heading': 'var(--ubb-font-sans)',

  'radius-sm': '0.25rem',
  'radius-md': '0.375rem',
  'radius-lg': '0.5rem',
  'radius-xl': '0.75rem',

  'border-width': '1px',
  'border-width-strong': '1px',

  'shadow-xs': '0 1px 2px 0 oklch(0 0 0 / 0.05)',
  'shadow-sm': '0 1px 2px 0 oklch(0 0 0 / 0.3)',
  'shadow-md': '0 4px 6px -1px oklch(0 0 0 / 0.4)',
  'shadow-lg': '0 10px 15px -3px oklch(0 0 0 / 0.5)',

  spacing: '0.25rem',

  'case-heading': 'none',
  'tracking-heading': '0em',
  'tracking-body': '0em',
}
