/**
 * Custom themes (#74): import a theme as a JSON object of token values, validated against an
 * allowlist, never a stylesheet (THREAT_MODEL.md, "Why custom themes are JSON, not CSS").
 *
 * The rule this file exists to keep: NO USER-SUPPLIED STRING REACHES THE PAGE AS CSS SYNTAX. Every
 * value is parsed into its parts (numbers, units, keywords, font names) and the string handed to the
 * CSSOM is REBUILT from those parts, so even a value that slipped past a pattern could not carry
 * `url()`, `;`, `{}`, `@import`, `calc()`, `var()` (one fixed reference aside), quotes or comments.
 * It is a grammar, not a denylist.
 *
 * A custom theme is `{ "name", "mode", "tokens" }`. `mode` is `dark` or `light` and decides the
 * `data-theme` the vendored components key off. `tokens` may leave any token out; a missing one comes
 * from the built-in theme of the same mode (Refined Terminal for dark, Zine for light), so an author
 * can change a few values. The MERGED theme must then pass `themeProblems`, the same accessibility
 * checks the built-in themes pass (readable text pairs, a visible input edge and focus ring): a theme
 * that makes text unreadable, which could also hide a warning or a key fingerprint, is refused.
 */

import { themeProblems } from './themeChecks'
import { BUILT_IN_THEMES, type BuiltInTheme } from './themes'
import {
  BORDER_STYLE_VALUES,
  CASE_VALUES,
  TOKENS,
  TOKEN_NAMES,
  headingPairProblem,
  type Theme,
} from './tokens'

export interface CustomTheme extends BuiltInTheme {
  readonly custom: true
}

export type CustomThemeResult =
  | { readonly ok: true; readonly theme: CustomTheme }
  | { readonly ok: false; readonly errors: readonly string[] }

/** Most characters of pasted JSON read at all. A full theme is about 2 KB. */
export const MAX_THEME_TEXT = 8192
/** Most custom themes kept in one browser. */
export const MAX_CUSTOM_THEMES = 5

const TOP_LEVEL = ['name', 'mode', 'tokens']
const NUM = String.raw`(?:\d+(?:\.\d+)?|\.\d+)`
const COLOR = new RegExp(String.raw`^oklch\(\s*(${NUM})\s+(${NUM})\s+(${NUM})\s*\)$`)
const NAME = /^[\p{L}\p{N}][\p{L}\p{N} ._'-]{0,39}$/u
const FONT_NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,48}$/
const GENERIC_FONTS = [
  'serif',
  'sans-serif',
  'monospace',
  'system-ui',
  'ui-serif',
  'ui-sans-serif',
  'ui-monospace',
  'ui-rounded',
]
const CSS_WIDE = ['inherit', 'initial', 'unset', 'revert', 'revert-layer', 'default']
/** The one reference a value may hold: the heading font following the body font, as the built-ins do. */
const SANS_REFERENCE = 'var(--ubb-font-sans)'

/** Bounds, in px (1rem = 1em = 16px), for each length token. */
const LENGTH_BOUNDS: Readonly<Record<string, readonly [number, number]>> = {
  'radius-sm': [0, 32],
  'radius-md': [0, 32],
  'radius-lg': [0, 32],
  'radius-xl': [0, 32],
  'border-width': [0, 4],
  'border-width-strong': [0, 12],
  spacing: [2.4, 6],
  'tracking-heading': [0, 4.8],
  'tracking-body': [0, 4.8],
}

const fmt = (n: number): string => String(Number(n.toFixed(4)))

function parseColor(value: string): { l: number; c: number; h: number } | null {
  if (value.length > 60) return null
  const m = COLOR.exec(value.trim())
  if (m === null) return null
  const [l, c, h] = [Number(m[1]), Number(m[2]), Number(m[3])]
  return l <= 1 && c <= 0.5 && h <= 360 ? { l, c, h } : null
}

function colorValue(value: string): string | null {
  const p = parseColor(value)
  return p === null ? null : `oklch(${fmt(p.l)} ${fmt(p.c)} ${fmt(p.h)})`
}

/** A length with an optional unit (bare only for 0), as [px, rebuilt text]. */
function parseLength(value: string, allowNegative: boolean): { px: number; text: string } | null {
  const m = new RegExp(String.raw`^(-?)(${NUM})(px|rem|em)?$`).exec(value.trim())
  if (m === null || value.length > 20) return null
  const n = Number(m[2])
  if ((m[1] === '-' && !allowNegative) || !Number.isFinite(n)) return null
  const unit = m[3] ?? ''
  if (unit === '' && n !== 0) return null
  const signed = m[1] === '-' ? -n : n
  return {
    px: signed * (unit === 'px' ? 1 : 16),
    text: n === 0 && unit === '' ? '0' : `${fmt(signed)}${unit}`,
  }
}

function lengthValue(name: string, value: string): string | null {
  const bounds = LENGTH_BOUNDS[name]
  const p = parseLength(value, false)
  if (bounds === undefined || p === null) return null
  return p.px >= bounds[0] && p.px <= bounds[1] ? p.text : null
}

function oneShadow(value: string): string | null {
  const m = new RegExp(
    String.raw`^(\S+)\s+(\S+)\s+(\S+)(?:\s+(\S+))?\s+(transparent|oklch\([^)]*\))$`,
  ).exec(value.trim())
  if (m === null) return null
  const parts: string[] = []
  for (const [raw, lo, hi] of [
    [m[1], -40, 40],
    [m[2], -40, 40],
    [m[3], 0, 60],
    [m[4], -40, 40],
  ] as const) {
    if (raw === undefined) continue
    const p = parseLength(raw, true)
    if (p === null || p.px < lo || p.px > hi || /(rem|em)$/.test(p.text)) return null
    parts.push(p.text)
  }
  const colorText = m[5] ?? ''
  if (colorText === 'transparent') return `${parts.join(' ')} transparent`
  const alpha = /^oklch\(([^/]*?)(?:\s*\/\s*(\S+?))?\s*\)$/.exec(colorText)
  if (alpha === null) return null
  const color = colorValue(`oklch(${alpha[1] ?? ''})`)
  if (color === null) return null
  if (alpha[2] === undefined) return `${parts.join(' ')} ${color}`
  const a = new RegExp(`^${NUM}$`).test(alpha[2]) ? Number(alpha[2]) : NaN
  if (!(a >= 0 && a <= 1)) return null
  return `${parts.join(' ')} ${color.slice(0, -1)} / ${fmt(a)})`
}

function shadowValue(value: string): string | null {
  if (value.length > 300) return null
  const list = value.split(',')
  if (list.length > 3) return null
  const rebuilt = list.map(oneShadow)
  return rebuilt.every((s): s is string => s !== null) ? rebuilt.join(', ') : null
}

function fontValue(name: string, value: string): string | null {
  if (value === SANS_REFERENCE) return name === 'font-heading' ? value : null
  if (value.length > 300) return null
  const entries = value.split(',').map((e) => e.trim())
  if (entries.length > 10) return null
  const out: string[] = []
  for (const entry of entries) {
    const unquoted = /^(['"])(.*)\1$/.exec(entry)?.[2] ?? entry
    if (GENERIC_FONTS.includes(unquoted.toLowerCase()) && unquoted === entry) {
      out.push(entry.toLowerCase())
    } else if (FONT_NAME.test(unquoted) && !CSS_WIDE.includes(unquoted.toLowerCase())) {
      out.push(`'${unquoted}'`)
    } else {
      return null
    }
  }
  return out.join(', ')
}

/** One token's value, rebuilt from its parts, or null if it is not allowed for that token. */
export function tokenValue(name: string, value: unknown): string | null {
  const spec = TOKENS.find((t) => t.name === name)
  if (spec === undefined || typeof value !== 'string') return null
  switch (spec.kind) {
    case 'color':
      return colorValue(value)
    case 'font':
      return fontValue(name, value)
    case 'length':
    case 'tracking':
      return lengthValue(name, value)
    case 'shadow':
      return shadowValue(value)
    case 'case':
      return (CASE_VALUES as readonly string[]).includes(value) ? value : null
    case 'border-style':
      return (BORDER_STYLE_VALUES as readonly string[]).includes(value) ? value : null
  }
}

/** A short stable hash, so one name is always one id and a different name never collides by slug. */
function hash(text: string): string {
  let h = 2166136261
  for (const ch of text) h = Math.imul(h ^ ch.codePointAt(0)!, 16777619) >>> 0
  return h.toString(36)
}

export function customThemeId(name: string): string {
  const slug = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 24)
  return `custom-${slug === '' ? 'theme' : slug}-${hash(name)}`
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** The token set a missing value is filled from: the built-in of the same mode. */
function baseTokens(mode: 'dark' | 'light'): Theme {
  const id = mode === 'dark' ? 'refined-terminal' : 'zine'
  return (BUILT_IN_THEMES.find((t) => t.id === id) as BuiltInTheme).tokens
}

/** Validate pasted theme JSON. Either the finished theme or every reason it was refused. */
export function validateCustomTheme(text: string): CustomThemeResult {
  if (text.length > MAX_THEME_TEXT) {
    return {
      ok: false,
      errors: [`The theme is too long (the limit is ${MAX_THEME_TEXT} characters).`],
    }
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    return { ok: false, errors: ['This is not valid JSON.'] }
  }
  if (!isPlainObject(parsed)) {
    return { ok: false, errors: ['A theme is a JSON object with a name, a mode and tokens.'] }
  }
  const errors: string[] = []
  for (const key of Object.keys(parsed)) {
    if (!TOP_LEVEL.includes(key)) errors.push(`Unknown field "${key.slice(0, 40)}".`)
  }

  const rawName = typeof parsed['name'] === 'string' ? parsed['name'].trim() : ''
  if (!NAME.test(rawName)) {
    errors.push('"name" must be 1 to 40 letters, numbers, spaces or . _ - \' characters.')
  }
  const mode = parsed['mode']
  if (mode !== 'dark' && mode !== 'light') errors.push('"mode" must be "dark" or "light".')
  const given = parsed['tokens']
  if (!isPlainObject(given)) errors.push('"tokens" must be an object of token values.')
  if (errors.length > 0 || !isPlainObject(given) || (mode !== 'dark' && mode !== 'light')) {
    return { ok: false, errors }
  }

  // The base goes through the same rebuild as the author's values, so the result is the same
  // whether it is read now or back from storage.
  const tokens: Record<string, string> = {}
  for (const [name, value] of Object.entries(baseTokens(mode))) {
    tokens[name] = tokenValue(name, value) ?? value
  }
  for (const [name, value] of Object.entries(given)) {
    if (!TOKEN_NAMES.includes(name)) {
      errors.push(`Unknown token "${name.slice(0, 40)}".`)
      continue
    }
    const clean = tokenValue(name, value)
    if (clean === null) errors.push(`The value of "${name}" is not allowed.`)
    else tokens[name] = clean
  }
  if (errors.length > 0) return { ok: false, errors }

  const pair = headingPairProblem(tokens)
  const problems = [...(pair === null ? [] : [pair]), ...themeProblems(tokens)]
  if (problems.length > 0) return { ok: false, errors: problems }

  return {
    ok: true,
    theme: { id: customThemeId(rawName), name: rawName, mode, tokens, custom: true },
  }
}

/** A theme as the JSON a person can copy and edit: name, mode and every token. */
export function exportThemeJson(theme: { name: string; mode: string; tokens: Theme }): string {
  return JSON.stringify({ name: theme.name, mode: theme.mode, tokens: theme.tokens }, null, 2)
}
