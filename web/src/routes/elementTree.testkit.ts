// Test helper: walks the elements a function component returns, so a test can
// find a button and call its real onClick. web/ has no DOM, and a component with
// no hooks can be called as a plain function. Not a test file itself.

import { isValidElement, type ReactElement, type ReactNode } from 'react'

export type AnyElement = ReactElement<Record<string, unknown>>

/** Every element in the tree, depth first. */
export function elementsOf(node: ReactNode): AnyElement[] {
  if (Array.isArray(node)) return node.flatMap(elementsOf)
  if (!isValidElement<Record<string, unknown>>(node)) return []
  return [node, ...elementsOf(node.props['children'] as ReactNode)]
}
