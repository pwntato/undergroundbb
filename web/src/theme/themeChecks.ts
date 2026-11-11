import { contrastRatio, translucentContrast } from './contrast'
import {
  BORDER_STYLE_VALUES,
  CASE_VALUES,
  TOKEN_NAMES,
  headingPairProblem,
  type Theme,
} from './tokens'

/** The text pairs every theme must keep readable (WCAG AA, 4.5:1): foreground, background, what it is. */
export const TEXT_PAIRS: ReadonlyArray<readonly [string, string, string]> = [
  ['foreground', 'background', 'body text'],
  ['foreground', 'card', 'text on a card'],
  ['foreground', 'surface', 'text on a surface'],
  ['muted-foreground', 'background', 'secondary text'],
  ['muted-foreground', 'card', 'secondary text on a card'],
  ['muted-foreground', 'muted', 'secondary text on a muted block'],
  ['primary-foreground', 'primary', 'button label'],
  ['primary', 'background', 'accent text and links on the page'],
  ['primary', 'card', 'accent text on a card'],
  ['accent-foreground', 'accent', 'hovered item'],
  ['primary', 'accent', 'accent text on a hovered item'],
  ['secondary-foreground', 'secondary', 'secondary button'],
  ['destructive', 'background', 'error text'],
  ['destructive', 'card', 'error text on a card'],
  ['destructive-foreground', 'destructive', 'destructive label'],
  // Text can land on any of the panel fills, not only the page: a hovered row, a muted block, a surface.
  ['muted-foreground', 'accent', 'secondary text on a hovered item'],
  ['muted-foreground', 'secondary', 'secondary text on a secondary block'],
  ['muted-foreground', 'surface', 'secondary text on a surface'],
  ['primary', 'muted', 'accent text on a muted block'],
  ['primary', 'secondary', 'accent text on a secondary block'],
  ['primary', 'surface', 'accent text on a surface'],
  ['destructive', 'muted', 'error text on a muted block'],
  ['destructive', 'surface', 'error text on a surface'],
  ['destructive', 'accent', 'error text on a hovered item'],
  ['foreground', 'muted', 'text on a muted block'],
  ['foreground', 'accent', 'text on a hovered item'],
  ['foreground', 'secondary', 'text on a secondary block'],
]

/**
 * Everything a built-in theme has to satisfy, as a list of problems (empty when it is fine): a value
 * for every token and nothing else, a legal heading pair and border style, readable text pairs, an input
 * border that shows against the page and cards at 3:1, and a
 * focus ring that is visible at full strength and as the 50% halo the components draw.
 */
export function themeProblems(theme: Theme): string[] {
  const problems: string[] = []
  const names = new Set(TOKEN_NAMES)
  for (const n of TOKEN_NAMES) if (!(n in theme)) problems.push(`missing token ${n}`)
  for (const n of Object.keys(theme)) if (!names.has(n)) problems.push(`unknown token ${n}`)
  if (problems.length > 0) return problems

  const caseValue = theme['case-heading'] ?? ''
  if (!(CASE_VALUES as readonly string[]).includes(caseValue))
    problems.push(`case-heading ${caseValue}`)
  const style = theme['border-style'] ?? ''
  if (!(BORDER_STYLE_VALUES as readonly string[]).includes(style))
    problems.push(`border-style ${style}`)
  const pair = headingPairProblem(theme)
  if (pair !== null) problems.push(pair)

  for (const [fg, bg, what] of TEXT_PAIRS) {
    const ratio = contrastRatio(theme[fg] ?? '', theme[bg] ?? '')
    if (ratio < 4.5) problems.push(`${fg} on ${bg} (${what}) is ${ratio.toFixed(2)}:1, needs 4.5`)
  }
  // WCAG 1.4.11: the edge of a form control has to be seen against what it sits on, at 3:1.
  for (const ground of ['background', 'card']) {
    const edge = contrastRatio(theme['input'] ?? '', theme[ground] ?? '')
    if (edge < 3) problems.push(`input border on ${ground} is ${edge.toFixed(2)}:1, needs 3`)
  }
  const ring = theme['ring'] ?? ''
  for (const ground of ['background', 'card']) {
    const g = theme[ground] ?? ''
    const full = contrastRatio(ring, g)
    if (full < 3) problems.push(`ring on ${ground} is ${full.toFixed(2)}:1, needs 3`)
    const halo = translucentContrast(ring, g, 0.5)
    if (halo < 3) problems.push(`ring/50 on ${ground} is ${halo.toFixed(2)}:1, needs 3`)
  }
  return problems
}
