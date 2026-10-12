// Whether the crypto worker's liveKeys cache is warm for this session's
// account (#143). A reload, a new tab or a deploy clears the cache while the
// session cookie stays valid, so a signing screen asks up front and shows
// ReauthenticateStep before the user fills anything in, instead of finding out
// when the submit throws. The submit-time handling stays as the fallback.

import { useEffect, useState } from 'react'
import { hasLiveKeys } from '@/lib/crypto/worker-client'

export type LiveKeysStatus = 'checking' | 'warm' | 'cold'

/**
 * 'cold' only when the worker says so. A check that itself fails reports
 * 'warm': the screen then behaves as it did before this check existed, and
 * the signing call's own cold-cache handling still catches a real one.
 */
export async function checkLiveKeys(
  userId: string,
  check: (userId: string) => Promise<boolean>,
): Promise<'warm' | 'cold'> {
  try {
    return (await check(userId)) ? 'warm' : 'cold'
  } catch {
    return 'warm'
  }
}

/**
 * The cache's state for userId (null while there is no session: stays
 * 'checking'), markWarm for once ReauthenticateStep has refilled it or the
 * user chose to carry on without, and markCold for a signing call that found
 * the cache cold after all (e.g. the user cancelled the step), which brings
 * the step back instead of a message that points at a login that cannot help.
 */
export function useLiveKeys(userId: string | null): {
  readonly status: LiveKeysStatus
  readonly markWarm: () => void
  readonly markCold: () => void
} {
  const [status, setStatus] = useState<LiveKeysStatus>('checking')
  useEffect(() => {
    if (userId === null) {
      return
    }
    let cancelled = false
    void checkLiveKeys(userId, hasLiveKeys).then((result) => {
      if (!cancelled) setStatus(result)
    })
    return () => {
      cancelled = true
    }
  }, [userId])
  return {
    status,
    markWarm: () => {
      setStatus('warm')
    },
    markCold: () => {
      setStatus('cold')
    },
  }
}
