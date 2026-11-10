/**
 * WCAG contrast for the oklch() colors the themes use, so a theme's text pairs can be checked
 * without a browser. Only the plain `oklch(L C H)` form is read (no alpha, no percentages).
 */

export function parseOklch(value: string): { l: number; c: number; h: number } | null {
  const m = /^oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\)$/.exec(value.trim())
  if (m === null) return null
  return { l: Number(m[1]), c: Number(m[2]), h: Number(m[3]) }
}

/** oklch to linear sRGB, each channel clamped to 0..1 (Bjorn Ottosson's matrices). */
function toLinearSrgb({ l, c, h }: { l: number; c: number; h: number }): [number, number, number] {
  const a = c * Math.cos((h * Math.PI) / 180)
  const b = c * Math.sin((h * Math.PI) / 180)
  const l_ = (l + 0.3963377774 * a + 0.2158037573 * b) ** 3
  const m_ = (l - 0.1055613458 * a - 0.0638541728 * b) ** 3
  const s_ = (l - 0.0894841775 * a - 1.291485548 * b) ** 3
  const r = 4.0767416621 * l_ - 3.3077115913 * m_ + 0.2309699292 * s_
  const g = -1.2684380046 * l_ + 2.6097574011 * m_ - 0.3413193965 * s_
  const bl = -0.0041960863 * l_ - 0.7034186147 * m_ + 1.707614701 * s_
  const clamp = (x: number) => Math.min(1, Math.max(0, x))
  return [clamp(r), clamp(g), clamp(bl)]
}

function luminance(value: string): number {
  const parsed = parseOklch(value)
  if (parsed === null) throw new Error(`not a plain oklch() color: ${value}`)
  const [r, g, b] = toLinearSrgb(parsed)
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** The WCAG 2 contrast ratio between two colors, 1 to 21. */
export function contrastRatio(a: string, b: string): number {
  const la = luminance(a)
  const lb = luminance(b)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}
