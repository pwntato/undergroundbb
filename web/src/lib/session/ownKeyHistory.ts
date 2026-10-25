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

/** A history, or why there is none: a read failed, or what was served did not verify. */
type Loaded = { readonly history: OwnKeyHistory | null; readonly failure: string | null }

export type OwnKeyHistoryLoader = ((ownSigningKey: Uint8Array) => Promise<OwnKeyHistory | null>) & {
  /**
   * Why the history could not be loaded, or null when it loaded. Answers from
   * the same cached read as the loader itself, so asking costs nothing.
   */
  readonly failure: (ownSigningKey: Uint8Array) => Promise<string | null>
}

export function makeOwnKeyHistoryLoader(
  userId: string,
  api: OwnKeyHistoryApi = { getUserDetail, listKeyChangeRosters },
): OwnKeyHistoryLoader {
  const cache = new Map<string, Promise<Loaded>>()
  const load = async (ownSigningKey: Uint8Array): Promise<Loaded> => {
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
      return history === null
        ? { history, failure: 'the history the server served does not verify' }
        : { history, failure: null }
    } catch (err) {
      return { history: null, failure: err instanceof Error ? err.message : String(err) }
    }
  }
  const loaded = (ownSigningKey: Uint8Array): Promise<Loaded> => {
    const cacheKey = bytesToBase64(ownSigningKey)
    let hit = cache.get(cacheKey)
    if (hit === undefined) {
      hit = load(ownSigningKey)
      cache.set(cacheKey, hit)
    }
    return hit
  }
  return Object.assign(async (ownSigningKey: Uint8Array) => (await loaded(ownSigningKey)).history, {
    failure: async (ownSigningKey: Uint8Array) => (await loaded(ownSigningKey)).failure,
  })
}
