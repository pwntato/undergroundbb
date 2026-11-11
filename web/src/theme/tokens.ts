/**
 * The theme token vocabulary (#48): every value a theme can set, and nothing else.
 *
 * It was drawn up against Zine first because Zine is the hardest theme to express: hard offset
 * shadows, zero radius, thick borders, uppercase headings at display scale. A vocabulary that holds
 * Zine holds Refined Terminal and BBS Revival without needing anything extra.
 *
 * A theme is a JSON object of these values and never a stylesheet (see THREAT_MODEL.md, "Why custom
 * themes are JSON, not CSS"). This list is the allowlist the custom-theme validator (#74) checks
 * against, and `src/index.css` must declare a default for every entry (tokens.test.ts holds the two
 * together).
 */

export type TokenKind =
  'color' | 'font' | 'length' | 'shadow' | 'case' | 'tracking' | 'border-style'

export interface TokenSpec {
  /** Key in a theme object, e.g. `radius-md`. */
  readonly name: string
  /** The custom property that carries it, always `--ubb-<name>`. */
  readonly cssVar: string
  readonly kind: TokenKind
}

function token(name: string, kind: TokenKind): TokenSpec {
  return { name, cssVar: `--ubb-${name}`, kind }
}

const COLORS = [
  'background',
  'foreground',
  'muted',
  'muted-foreground',
  'surface',
  'surface-foreground',
  'card',
  'card-foreground',
  'border',
  'input',
  'ring',
  'primary',
  'primary-foreground',
  'accent',
  'accent-foreground',
  'secondary',
  'secondary-foreground',
  'destructive',
  'destructive-foreground',
] as const

export const TOKENS: readonly TokenSpec[] = [
  ...COLORS.map((name) => token(name, 'color')),

  token('font-sans', 'font'),
  token('font-mono', 'font'),
  token('font-heading', 'font'),

  token('radius-sm', 'length'),
  token('radius-md', 'length'),
  token('radius-lg', 'length'),
  token('radius-xl', 'length'),

  // The default border (Tailwind's `border`) and the heavy one (`border-2`-style emphasis).
  token('border-width', 'length'),
  token('border-width-strong', 'length'),
  // solid, or double and dashed for box-drawing rules (double only shows at 3px and up).
  token('border-style', 'border-style'),

  token('shadow-xs', 'shadow'),
  token('shadow-sm', 'shadow'),
  token('shadow-md', 'shadow'),
  token('shadow-lg', 'shadow'),

  // The base unit every spacing utility multiplies, so one value sets how dense the whole page is.
  token('spacing', 'length'),

  // text-transform and letter-spacing for headings travel together (see headingPairProblem).
  token('case-heading', 'case'),
  token('tracking-heading', 'tracking'),
  token('tracking-body', 'tracking'),
]

/** A theme: a value for every token, keyed by token name. Plain strings, so it is JSON. */
export type Theme = Readonly<Record<string, string>>

export const TOKEN_NAMES: readonly string[] = TOKENS.map((t) => t.name)

/** The values `--ubb-case-heading` may take. Anything else is refused by the validator. */
export const CASE_VALUES = ['none', 'uppercase', 'lowercase', 'capitalize'] as const

/** The values `--ubb-border-style` may take. Anything else is refused by the validator. */
export const BORDER_STYLE_VALUES = ['solid', 'dashed', 'dotted', 'double'] as const

/** A plain length: digits, an optional fraction, and a unit. No sign, calc(), percentage or keyword. */
const PLAIN_LENGTH = /^(\d*\.)?\d+(em|rem|px)$/

/**
 * Uppercase text with no letter-spacing is hard to read, so a theme that uppercases its headings has
 * to open them up too: a plain length strictly above zero (negative spacing is tighter than none,
 * which makes it worse). Returns the problem, or null when the pair is fine.
 */
export function headingPairProblem(values: {
  'case-heading'?: string
  'tracking-heading'?: string
}): string | null {
  if (values['case-heading'] !== 'uppercase') return null
  const tracking = (values['tracking-heading'] ?? '0').trim()
  if (!PLAIN_LENGTH.test(tracking) || !(parseFloat(tracking) > 0)) {
    return 'Uppercase headings need a letter-spacing above zero, written as a length such as 0.08em.'
  }
  return null
}
