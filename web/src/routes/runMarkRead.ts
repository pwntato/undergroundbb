// Marking notifications read in batches (#69). DynamoDB has no bulk attribute update, so the server
// takes up to MARK_READ_BATCH ids per request; a longer list is several requests, and one that
// fails stops the run, leaving the rest unread rather than claiming they are read.

import { MARK_READ_BATCH } from '@/lib/api/notifications'
import { trackMarkRead } from './markReadTracker'

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

/**
 * Whether the "couldn't mark those" alert shows after a mark finishes. A request the user started
 * with the button (`fresh`) replaces the alert with its own result; any other (a row opened in the
 * list) can only add one, so a later success cannot hide a failure that left rows unread.
 */
export function markFailedAfter(previous: boolean, failed: boolean, fresh: boolean): boolean {
  return fresh ? failed : previous || failed
}

/**
 * A mark-read run the header and Home can see: registered with the tracker while it is in flight,
 * so a count waits for it and a finished one makes the header count again (#145).
 */
export function runTrackedMarkRead(
  ids: readonly string[],
  mark: (batch: readonly string[]) => Promise<void>,
): Promise<MarkReadResult> {
  return trackMarkRead(runMarkRead(ids, mark))
}
