import { describe, expect, it, vi } from 'vitest'
import { generateSigningKey } from '@/lib/crypto/ed25519'
import { makeKeyChange, rowId } from '@/lib/crypto/own-history.testkit'
import type { UserDetail } from '@/lib/api/users'
import { makeOwnKeyHistoryLoader, type OwnKeyHistoryApi } from './ownKeyHistory'

const ME = 'a0000000-0000-4000-8000-000000000001'
const k0 = generateSigningKey()
const k1 = generateSigningKey()

function api(over: Partial<OwnKeyHistoryApi> = {}, listed = true) {
  const id = rowId('PIN#x', new Uint8Array(64))
  const kc = makeKeyChange({
    userId: ME,
    from: k0,
    to: k1,
    epoch: 1,
    day: '2026-10-01',
    listed: listed ? [id] : [],
  })
  const detail = { keyChanges: [kc.change] } as unknown as UserDetail
  const out: OwnKeyHistoryApi = {
    getUserDetail: vi.fn(() => Promise.resolve(detail)),
    listKeyChangeRosters: vi.fn(() => Promise.resolve([kc.roster])),
    ...over,
  }
  return out
}

describe('makeOwnKeyHistoryLoader', () => {
  it('builds the history from the chain and the rosters, and caches it', async () => {
    const a = api()
    const load = makeOwnKeyHistoryLoader(ME, a)
    const h = await load(k1.publicKey)
    expect(h?.links).toHaveLength(1)
    expect(h?.links[0]?.roster).toHaveLength(1)
    await load(k1.publicKey)
    expect(a.getUserDetail).toHaveBeenCalledTimes(1)
  })

  it('is null when the chain does not end at the key the caller holds, and does not cache it', async () => {
    const a = api()
    const load = makeOwnKeyHistoryLoader(ME, a)
    expect(await load(generateSigningKey().publicKey)).toBeNull()
    expect(await load(generateSigningKey().publicKey)).toBeNull()
    expect(a.getUserDetail).toHaveBeenCalledTimes(2)
  })

  it('is null, not a throw, when either read fails, and tries again next time', async () => {
    let fail = true
    const a = api({
      listKeyChangeRosters: vi.fn(() =>
        fail ? Promise.reject(new Error('offline')) : Promise.resolve([]),
      ),
    })
    const load = makeOwnKeyHistoryLoader(ME, a)
    expect(await load(k1.publicKey)).toBeNull()
    fail = false
    expect((await load(k1.publicKey))?.links).toHaveLength(1)
  })
})
