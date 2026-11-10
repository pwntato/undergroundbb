import { describe, expect, it, vi } from 'vitest'
import { groupLabelsOf } from './groupLabels'
import type { DisplayGroup } from './runListGroups'

function group(over: Partial<DisplayGroup>): DisplayGroup {
  return {
    groupId: 'g',
    visibility: 'private',
    role: 'member',
    generation: 0,
    noRotation: true,
    nameGeneration: 0,
    displayName: 'Book Club',
    displayDescription: '',
    nameStatus: 'decrypted',
    ...over,
  }
}
const dm = (id: string, with_: string): DisplayGroup =>
  group({ groupId: id, groupType: 'dm', dmWith: with_, displayName: null, nameStatus: 'dm' })

describe('groupLabelsOf', () => {
  it('labels a DM by the other person and an ordinary group by its name, reading names once', async () => {
    const resolve = vi.fn(
      async () =>
        new Map([
          ['u1', 'rex'],
          ['u2', 'sam'],
        ]),
    )
    const out = await groupLabelsOf(
      [group({ groupId: 'a' }), dm('d1', 'u1'), dm('d2', 'u2')],
      resolve,
    )
    expect(Object.fromEntries(out)).toEqual({ a: 'Book Club', d1: 'rex', d2: 'sam' })
    expect(resolve).toHaveBeenCalledExactlyOnceWith(['u1', 'u2'])
  })

  it('reads no names when there is no DM', async () => {
    const resolve = vi.fn(async () => new Map<string, string>())
    await groupLabelsOf([group({ groupId: 'a' })], resolve)
    expect(resolve).not.toHaveBeenCalled()
  })

  it('shows a plain word, never an id fragment, for a name that could not be read', async () => {
    const out = await groupLabelsOf(
      [dm('d1', '3f2a9c1b-1111-4222-8333-444444444444')],
      async () => new Map(),
    )
    expect(out.get('d1')).toBe('Direct message')
  })

  it('names a deleted account as such', async () => {
    const out = await groupLabelsOf([dm('d1', 'u1')], async () => new Map([['u1', '']]))
    expect(out.get('d1')).toBe('deleted user')
  })
})
