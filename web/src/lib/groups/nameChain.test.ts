import { describe, expect, it, vi } from 'vitest'
import type { KeychainLink, KeychainResponse } from '@/lib/api/groups'
import { fetchNameChain } from './nameChain'

const link = (generation: number): KeychainLink => ({
  generation,
  wrapped: { nonce: `n${String(generation)}`, ciphertext: `c${String(generation)}` },
})

const gens = (links: readonly KeychainLink[] | undefined) => links?.map((l) => l.generation).sort()

describe('fetchNameChain', () => {
  it('needs nothing, and makes no request, when the name is at the member generation', async () => {
    const get = vi.fn()
    expect(await fetchNameChain(get, 'g1', 2, 2)).toEqual([])
    expect(get).not.toHaveBeenCalled()
  })

  it('asks for exactly nameGeneration..generation-1', async () => {
    const get = vi.fn().mockResolvedValue({ links: [link(1), link(2)] })
    expect(gens(await fetchNameChain(get, 'g1', 1, 3))).toEqual([1, 2])
    expect(get).toHaveBeenCalledWith('g1', 1, 2)
  })

  it('follows nextFrom across pages', async () => {
    const get = vi
      .fn<(g: string, from: number, to: number) => Promise<KeychainResponse>>()
      .mockResolvedValueOnce({ links: [link(0), link(1)], nextFrom: 2 })
      .mockResolvedValueOnce({ links: [link(2)] })
    expect(gens(await fetchNameChain(get, 'g1', 0, 3))).toEqual([0, 1, 2])
    expect(get.mock.calls.map((c) => c[1])).toEqual([0, 2])
  })

  it('returns undefined when a link is missing from the range', async () => {
    const get = vi.fn().mockResolvedValue({ links: [link(0), link(2)] })
    expect(await fetchNameChain(get, 'g1', 0, 3)).toBeUndefined()
  })

  it('returns undefined, rather than throwing, when the request fails', async () => {
    const get = vi.fn().mockRejectedValue(new Error('offline'))
    expect(await fetchNameChain(get, 'g1', 0, 2)).toBeUndefined()
  })

  it('gives up on a server whose nextFrom does not advance', async () => {
    const get = vi.fn().mockResolvedValue({ links: [link(0)], nextFrom: 0 })
    expect(await fetchNameChain(get, 'g1', 0, 3)).toBeUndefined()
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('ignores links outside the requested range', async () => {
    const get = vi.fn().mockResolvedValue({ links: [link(0), link(1), link(9)] })
    expect(gens(await fetchNameChain(get, 'g1', 0, 2))).toEqual([0, 1])
  })
})
