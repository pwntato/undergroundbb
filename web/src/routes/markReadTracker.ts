// Mark-read requests in flight (#145). "Mark these read" sends its batches of 25 one after another
// and does not wait for them, so a user who goes straight Back could load Home, or the header's
// count, while rows are still unmarked and see a badge for notifications they just read. Anything
// that reads an unread count waits for `marksSettled()` first, and `onMarksSettled` tells the
// header to count again once a mark finishes.

let pending = 0
let waiters: Array<() => void> = []
const listeners = new Set<() => void>()

/** Registers a mark-read run; resolves with it. Never rejects on its own account. */
export async function trackMarkRead<T>(run: Promise<T>): Promise<T> {
  pending++
  try {
    return await run
  } finally {
    pending--
    if (pending === 0) {
      const ready = waiters
      waiters = []
      for (const w of ready) w()
      for (const l of [...listeners]) l()
    }
  }
}

/** Resolves when no tracked mark-read is in flight (at once when none is). */
export function marksSettled(): Promise<void> {
  if (pending === 0) return Promise.resolve()
  return new Promise((resolve) => waiters.push(resolve))
}

/** Calls `cb` each time the last in-flight mark-read finishes. Returns the unsubscribe. */
export function onMarksSettled(cb: () => void): () => void {
  listeners.add(cb)
  return () => {
    listeners.delete(cb)
  }
}
