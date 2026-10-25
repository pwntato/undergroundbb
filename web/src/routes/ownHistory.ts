// Shared by the runners that check the caller's own pins and records: asks the
// deps for the caller's verified key history (lib/crypto/own-history) and turns
// every failure into "no history", which makes the evaluators accept only the
// caller's current key. That is the same fail-closed behaviour as before
// rotation existed, so a failed read never accepts more.

import { ownKeys, type OwnKeyHistory } from '@/lib/crypto/own-history'

export interface OwnHistoryDeps {
  readonly loadOwnKeyHistory?: (ownSigningKey: Uint8Array) => Promise<OwnKeyHistory | null>
}

export async function ownHistoryFor(
  deps: OwnHistoryDeps,
  own: Uint8Array,
): Promise<OwnKeyHistory | undefined> {
  try {
    return (await deps.loadOwnKeyHistory?.(own)) ?? undefined
  } catch {
    return undefined
  }
}

/** Every signing key the caller has held, for checking records they signed over time. */
export async function ownSigningKeysFor(
  deps: OwnHistoryDeps,
  own: Uint8Array,
): Promise<Uint8Array[]> {
  const history = await ownHistoryFor(deps, own)
  return history === undefined ? [own] : ownKeys(history)
}
