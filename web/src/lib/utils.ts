import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

/**
 * Merge Tailwind class names, resolving conflicts in favour of the last one.
 * shadcn/ui components expect this helper at this path.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}
