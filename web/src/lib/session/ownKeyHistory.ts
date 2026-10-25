// Builds the caller's verified key history from what the server serves them:
// the KEYCHANGE# chain on GET /api/users/{self} and the rotation rosters on the
// first page of GET /api/pins. Verification and the trust rules are in
// lib/crypto/own-history; this only fetches.
//
// The result, including a failed or unverifiable one, is cached for the life of
// the loader (a job, or a screen effect; every retry builds a fresh one). A
// job asks at every pin check, so caching the failure keeps it to one pair of
// requests and keeps its answers the same from start to end. The history only
// grows, and a stale one can only make the evaluators accept less.

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
  const cache = new Map<string, Promise<OwnKeyHistory | null>>()
  const load = async (ownSigningKey: Uint8Array): Promise<OwnKeyHistory | null> => {
    try {
      const [detail, rosters] = await Promise.all([
        api.getUserDetail(userId),
        api.listKeyChangeRosters(),
      ])
      return buildOwnKeyHistory({ userId, ownSigningKey, changes: detail.keyChanges, rosters })
    } catch {
      return null
    }
  }
  return (ownSigningKey) => {
    const cacheKey = bytesToBase64(ownSigningKey)
    let hit = cache.get(cacheKey)
    if (hit === undefined) {
      hit = load(ownSigningKey)
      cache.set(cacheKey, hit)
    }
    return hit
  }
}
