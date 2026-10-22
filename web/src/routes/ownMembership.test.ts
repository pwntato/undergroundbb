import { describe, expect, it, vi } from 'vitest'
import type { GroupDetail, GroupListEntry } from '@/lib/api/groups'
import { makeGetOwnMembership } from './ownMembership'

const WRAP = { ephemeralPub: 'ZXBoZW1lcmFs', nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' }
const GRANT = 'GRANT#u#2026-10-22#aaaa'

function entry(over: Partial<GroupListEntry>): GroupListEntry {
  return {
    groupId: 'g1',
    visibility: 'private',
    role: 'admin',
    generation: 2,
    nameGeneration: 0,
    wrappedGroupKey: WRAP,
    ...over,
  }
}

function deps(groups: GroupListEntry[]) {
  return {
    listGroups: vi.fn().mockResolvedValue({ groups }),
    getGroup: vi.fn().mockResolvedValue({ myGrantSortKey: GRANT } as GroupDetail),
  }
}

describe('makeGetOwnMembership', () => {
  it('completes for a private group', async () => {
    const get = makeGetOwnMembership(deps([entry({})]))
    expect(await get('g1')).toEqual({ generation: 2, grantSortKey: GRANT, wrappedGroupKey: WRAP })
  })

  it('completes for a public group, whose entry carries the wrap too', async () => {
    const d = deps([entry({ groupId: 'pub', visibility: 'public', namePlaintext: 'Book Club' })])
    expect(await makeGetOwnMembership(d)('pub')).toEqual({
      generation: 2,
      grantSortKey: GRANT,
      wrappedGroupKey: WRAP,
    })
  })

  it('is null for a group that is not in the list, or whose entry has no wrap', async () => {
    const noWrap = entry({ groupId: 'x' })
    const { wrappedGroupKey: _omit, ...rest } = noWrap
    const get = makeGetOwnMembership(deps([rest as GroupListEntry]))
    expect(await get('x')).toBeNull()
    expect(await get('missing')).toBeNull()
  })

  it('lists the groups once across invites', async () => {
    const d = deps([entry({}), entry({ groupId: 'g2' })])
    const get = makeGetOwnMembership(d)
    await get('g1')
    await get('g2')
    expect(d.listGroups).toHaveBeenCalledTimes(1)
  })

  it('throws when the group detail has no grant of the caller', async () => {
    const d = deps([entry({})])
    d.getGroup.mockResolvedValue({} as GroupDetail)
    await expect(makeGetOwnMembership(d)('g1')).rejects.toThrow('own grant')
  })
})
