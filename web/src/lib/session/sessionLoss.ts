// Issue #228: the server answers 401 when a session cookie stops being honored
// (expired, or revoked by a logout on another device since #224), but each
// screen used to map that to its own message and leave SessionContext saying
// "logged in". This is the one place that notices, so the client drops its
// session state and RequireAuth sends the visitor to /login.
//
// It watches fetch rather than every API wrapper because the wrappers do not
// share a request helper. Only a 401 from a protected route counts: everything
// under /api/auth/ answers 401 for reasons that are not a lost session (a bad
// login signature, a wrong recovery code), and a 500 -- which is what a store
// failure deliberately is (#227) -- is never mistaken for a logout.

type FetchFn = typeof fetch

const AUTH_PREFIX = '/api/auth/'

/** True when a response to `input` with `status` means the session is gone. */
export function isSessionLoss(input: RequestInfo | URL, status: number, origin: string): boolean {
  if (status !== 401) return false
  const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url
  let url: URL
  try {
    url = new URL(raw, origin)
  } catch {
    return false
  }
  if (url.origin !== origin) return false
  return url.pathname.startsWith('/api/') && !url.pathname.startsWith(AUTH_PREFIX)
}

/** Wraps fetchImpl so onLost runs for every response isSessionLoss accepts. */
export function watchSessionLoss(fetchImpl: FetchFn, origin: string, onLost: () => void): FetchFn {
  return async (input, init) => {
    const res = await fetchImpl(input, init)
    if (isSessionLoss(input, res.status, origin)) onLost()
    return res
  }
}

/**
 * Replaces target.fetch with a watching wrapper and returns the undo, so a
 * StrictMode remount or a test leaves the original in place.
 */
export function installSessionLossWatcher(
  target: { fetch: FetchFn },
  origin: string,
  onLost: () => void,
): () => void {
  const original = target.fetch
  target.fetch = watchSessionLoss(original.bind(target), origin, onLost)
  return () => {
    target.fetch = original
  }
}
