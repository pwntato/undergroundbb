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

function luminanceOf([r, g, b]: [number, number, number]): number {
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function rgbOf(value: string): [number, number, number] {
  const parsed = parseOklch(value)
  if (parsed === null) throw new Error(`not a plain oklch() color: ${value}`)
  return toLinearSrgb(parsed)
}

function luminance(value: string): number {
  return luminanceOf(rgbOf(value))
}

const encode = (x: number) => (x <= 0.0031308 ? 12.92 * x : 1.055 * x ** (1 / 2.4) - 0.055)
const decode = (x: number) => (x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4)

/**
 * The contrast of `fg` drawn at `alpha` over `bg`, against that same `bg`: what a translucent
 * ring or halo (`ring-ring/50`) actually shows. Browsers composite in gamma-encoded sRGB, so the
 * mix is done there.
 */
export function translucentContrast(fg: string, bg: string, alpha: number): number {
  const f = rgbOf(fg).map(encode)
  const b = rgbOf(bg).map(encode)
  const mixed = f.map((c, i) => decode(alpha * c + (1 - alpha) * (b[i] ?? 0))) as [
    number,
    number,
    number,
  ]
  const lm = luminanceOf(mixed)
  const lb = luminance(bg)
  return (Math.max(lm, lb) + 0.05) / (Math.min(lm, lb) + 0.05)
}

/** The WCAG 2 contrast ratio between two colors, 1 to 21. */
export function contrastRatio(a: string, b: string): number {
  const la = luminance(a)
  const lb = luminance(b)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}
