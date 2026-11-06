// Marking notifications read in batches (#69). DynamoDB has no bulk attribute update, so the server
// takes up to MARK_READ_BATCH ids per request; a longer list is several requests, and one that
// fails stops the run, leaving the rest unread rather than claiming they are read.

import { MARK_READ_BATCH } from '@/lib/api/notifications'

export interface MarkReadResult {
  /** The ids the server confirmed. */
  readonly marked: readonly string[]
  /** True when a request failed before every id was marked. */
  readonly failed: boolean
}

export async function runMarkRead(
  ids: readonly string[],
  mark: (batch: readonly string[]) => Promise<void>,
): Promise<MarkReadResult> {
  const marked: string[] = []
  for (let i = 0; i < ids.length; i += MARK_READ_BATCH) {
    const batch = ids.slice(i, i + MARK_READ_BATCH)
    try {
      await mark(batch)
    } catch {
      return { marked, failed: true }
    }
    marked.push(...batch)
  }
  return { marked, failed: false }
}
