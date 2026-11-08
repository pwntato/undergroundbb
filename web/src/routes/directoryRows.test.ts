import { describe, expect, it } from 'vitest'
import type { DirectoryEntry } from '@/lib/api/directory'
import type { MyJoinRequest } from '@/lib/api/joinRequests'
import { directoryRows, snippet } from './directoryRows'

const e = (groupId: string, name = 'Book Club'): DirectoryEntry => ({ groupId, name })
const req = (
  groupId: string,
  status: 'pending' | 'denied',
  retryAfter?: string,
): MyJoinRequest => ({
  groupId,
  requestId: 'r-' + groupId,
  status,
  day: '2026-11-08',
  ...(retryAfter === undefined ? {} : { retryAfter }),
})

describe('directoryRows', () => {
  it('marks a member, a pending request, a declined one and a free group', () => {
    const rows = directoryRows(
      [e('aaaaaaaa-1'), e('bbbbbbbb-2'), e('cccccccc-3'), e('dddddddd-4')],
      new Set(['aaaaaaaa-1']),
      [req('bbbbbbbb-2', 'pending'), req('cccccccc-3', 'denied', '2026-11-15')],
    )
    expect(rows.map((r) => r.status)).toEqual([
      { kind: 'member' },
      { kind: 'pending' },
      { kind: 'declined', retryAfter: '2026-11-15' },
      { kind: 'available' },
    ])
  })

  it('shows membership even when a leftover request row exists', () => {
    const [row] = directoryRows([e('g-1')], new Set(['g-1']), [req('g-1', 'pending')])
    expect(row?.status).toEqual({ kind: 'member' })
  })

  it('keeps two groups with the same name apart by id, in the order given', () => {
    const rows = directoryRows([e('11111111-a'), e('22222222-b')], new Set(), [])
    expect(rows.map((r) => r.entry.name)).toEqual(['Book Club', 'Book Club'])
    expect(rows.map((r) => r.shortId)).toEqual(['11111111', '22222222'])
  })
})

describe('snippet', () => {
  it('leaves a short description alone and trims it', () => {
    expect(snippet('  hello  ')).toBe('hello')
    expect(snippet(undefined)).toBe('')
  })
  it('cuts a long one on a word boundary with an ellipsis, never past the limit', () => {
    const long = 'word '.repeat(100)
    const out = snippet(long, 20)
    expect(out.endsWith('…')).toBe(true)
    expect(out.length).toBeLessThanOrEqual(21)
    expect(out).not.toContain('wor…')
  })
  it('cuts mid-word when there is no usable space', () => {
    expect(snippet('x'.repeat(50), 10)).toBe('x'.repeat(10) + '…')
  })
})
