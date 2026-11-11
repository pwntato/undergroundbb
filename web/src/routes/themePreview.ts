import type { CSSProperties } from 'react'
import type { BuiltInTheme } from '@/theme/themes'

/**
 * Inline styles that draw a small sample of a theme from that theme's own token values, so the picker
 * can show every theme at once while only one is applied to the page. They cannot be utilities or
 * `--ubb-*` overrides on a wrapper: the Tailwind theme variables resolve at `:root`, so a child that
 * overrides `--ubb-*` would still paint with the page's theme.
 */
export interface ThemePreviewStyles {
  readonly frame: CSSProperties
  readonly heading: CSSProperties
  readonly body: CSSProperties
  readonly button: CSSProperties
}

/** A heading font token may refer to the sans token (`var(--ubb-font-sans)`); resolve it for the sample. */
function resolveFont(theme: BuiltInTheme, token: string): string {
  const value = theme.tokens[token] ?? ''
  return value === 'var(--ubb-font-sans)' ? (theme.tokens['font-sans'] ?? '') : value
}

export function themePreviewStyles(theme: BuiltInTheme): ThemePreviewStyles {
  const t = theme.tokens
  const unit = t['spacing'] ?? '0.25rem'
  return {
    frame: {
      background: t['background'] ?? '',
      color: t['foreground'] ?? '',
      fontFamily: resolveFont(theme, 'font-sans'),
      letterSpacing: t['tracking-body'] ?? '0em',
      border: `${t['border-width-strong']} ${t['border-style']} ${t['border']}`,
      borderRadius: t['radius-lg'] ?? '0',
      boxShadow: t['shadow-md'] ?? 'none',
      padding: `calc(${unit} * 3)`,
      display: 'flex',
      flexDirection: 'column',
      gap: `calc(${unit} * 2)`,
    },
    heading: {
      fontFamily: resolveFont(theme, 'font-heading'),
      textTransform: t['case-heading'] as CSSProperties['textTransform'],
      letterSpacing: t['tracking-heading'] ?? '0em',
      fontWeight: 700,
      fontSize: '1.125rem',
      lineHeight: 1.1,
    },
    body: { color: t['muted-foreground'] ?? '', fontSize: '0.75rem' },
    button: {
      alignSelf: 'flex-start',
      background: t['primary'] ?? '',
      color: t['primary-foreground'] ?? '',
      borderRadius: t['radius-md'] ?? '0',
      boxShadow: t['shadow-sm'] ?? 'none',
      padding: `calc(${unit} * 1) calc(${unit} * 3)`,
      fontSize: '0.75rem',
      fontWeight: 500,
    },
  }
}
