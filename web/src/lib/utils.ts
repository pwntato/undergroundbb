import { clsx, type ClassValue } from 'clsx'
import { extendTailwindMerge } from 'tailwind-merge'

/**
 * tailwind-merge does not know `border-strong` (the theme's heavy border, see index.css), and would
 * read it as a border colour, so a caller adding `border-destructive` would lose the border. Teaching
 * it that `border-strong` is a width makes it behave like `border`, `border-0` and `border-2`.
 */
const twMerge = extendTailwindMerge({
  extend: { classGroups: { 'border-w': ['border-strong'] } },
})

/**
 * Merge Tailwind class names, resolving conflicts in favour of the last one.
 * shadcn/ui components expect this helper at this path.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
