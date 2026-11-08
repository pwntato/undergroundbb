// Typed client for GET /api/groups/public (#71) -- see internal/handlers/directory.go. Public means
// discoverable, not readable: an entry is a group's id, plaintext name and description only.

import { ApiError } from './auth.js'
import { noteServerDate } from './serverClock.js'

export interface DirectoryEntry {
  readonly groupId: string
  readonly name: string
  readonly description?: string
}

export interface DirectoryPage {
  readonly groups: readonly DirectoryEntry[]
  readonly nextCursor?: string
}

/**
 * GET /api/groups/public?q=&limit=&cursor=. `q` is a case-sensitive name prefix. Names are NOT unique,
 * so a page can hold several entries with the same name: the id tells them apart. A cursor is only
 * valid with the `q` it was issued for (the server answers 400 otherwise).
 */
export async function listPublicGroups(
  opts: { readonly q?: string; readonly limit?: number; readonly cursor?: string } = {},
): Promise<DirectoryPage> {
  const params = new URLSearchParams()
  if (opts.q !== undefined && opts.q !== '') params.set('q', opts.q)
  if (opts.limit !== undefined) params.set('limit', String(opts.limit))
  if (opts.cursor !== undefined && opts.cursor !== '') params.set('cursor', opts.cursor)
  const qs = params.toString()
  const res = await fetch(`/api/groups/public${qs === '' ? '' : `?${qs}`}`, {
    credentials: 'same-origin',
  })
  noteServerDate(res)
  let data: unknown
  try {
    data = await res.json()
  } catch {
    throw new ApiError(res.status, res.statusText || 'malformed response')
  }
  if (!res.ok) {
    const message =
      typeof data === 'object' && data !== null && 'error' in data && typeof data.error === 'string'
        ? data.error
        : res.statusText || 'request failed'
    throw new ApiError(res.status, message)
  }
  return readPage(data, res.status)
}

/** A page whose shape is wrong is rejected, never shown as an empty or partial directory. */
function readPage(data: unknown, status: number): DirectoryPage {
  const bad = () => new ApiError(status, 'malformed response')
  if (
    typeof data !== 'object' ||
    data === null ||
    !('groups' in data) ||
    !Array.isArray(data.groups)
  ) {
    throw bad()
  }
  const groups: DirectoryEntry[] = []
  for (const g of data.groups as unknown[]) {
    if (typeof g !== 'object' || g === null) throw bad()
    const r = g as Record<string, unknown>
    if (typeof r['groupId'] !== 'string' || typeof r['name'] !== 'string') throw bad()
    if (r['description'] !== undefined && typeof r['description'] !== 'string') throw bad()
    groups.push({
      groupId: r['groupId'],
      name: r['name'],
      ...(typeof r['description'] === 'string' ? { description: r['description'] } : {}),
    })
  }
  const next = (data as Record<string, unknown>)['nextCursor']
  if (next !== undefined && typeof next !== 'string') throw bad()
  return { groups, ...(typeof next === 'string' && next !== '' ? { nextCursor: next } : {}) }
}
