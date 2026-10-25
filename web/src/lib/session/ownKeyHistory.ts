// Builds the caller's verified key history from what the server serves them:
// the KEYCHANGE# chain on GET /api/users/{self} and the rotation rosters on the
// first page of GET /api/pins. Verification and the trust rules are in
// lib/crypto/own-history; this only fetches.
//
// The result is cached for the life of the loader (a job, or a screen): the
// history only grows, and a stale one can only make the evaluators accept less.
// A failed or unverifiable read is not cached, so the next call tries again.

import { listKeyChangeRosters } from '@/lib/api/pins'
import { getUserDetail } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import { buildOwnKeyHistory, type OwnKeyHistory } from '@/lib/crypto/own-history'

export interface OwnKeyHistoryApi {
  readonly getUserDetail: typeof getUserDetail
  readonly listKeyChangeRosters: typeof listKeyChangeRosters
}

export function makeOwnKeyHistoryLoader(
  userId: string,
  api: OwnKeyHistoryApi = { getUserDetail, listKeyChangeRosters },
): (ownSigningKey: Uint8Array) => Promise<OwnKeyHistory | null> {
  const cache = new Map<string, OwnKeyHistory>()
  return async (ownSigningKey) => {
    const cacheKey = bytesToBase64(ownSigningKey)
    const hit = cache.get(cacheKey)
    if (hit !== undefined) return hit
    try {
      const [detail, rosters] = await Promise.all([
        api.getUserDetail(userId),
        api.listKeyChangeRosters(),
      ])
      const history = buildOwnKeyHistory({
        userId,
        ownSigningKey,
        changes: detail.keyChanges,
        rosters,
      })
      if (history !== null) cache.set(cacheKey, history)
      return history
    } catch {
      return null
    }
  }
}
