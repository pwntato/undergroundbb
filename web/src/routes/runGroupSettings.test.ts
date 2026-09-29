// Dependency-injected tests for runGroupSettings.ts -- same structure and
// reasoning as runListGroups.test.ts (node environment, no jsdom).

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import {
  loadGroupSettings,
  saveGroupSettings,
  type LoadSettingsDeps,
  type SaveSettingsDeps,
  type SettingsView,
} from './runGroupSettings'

const WRAPPED_KEY = { ephemeralPub: 'ZXBoZW1lcmFs', nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' }
const NAME_CT = { nonce: 'bm9uY2Ux', ciphertext: 'bmFtZS1jdA==' }
const DESC_CT = { nonce: 'bm9uY2Uy', ciphertext: 'ZGVzYy1jdA==' }
const NEW_NAME_CT = { nonce: 'bmV3bmFtZQ==', ciphertext: 'bmV3LW5hbWU=' }
const NEW_DESC_CT = { nonce: 'bmV3ZGVzYw==', ciphertext: 'bmV3LWRlc2M=' }

function publicDetail(overrides: Partial<GroupDetail> = {}): GroupDetail {
  return {
    groupId: 'pub-1',
    visibility: 'public',
    role: 'admin',
    generation: 0,
    nameGeneration: 0,
    namePlaintext: 'Book Club',
    descriptionPlaintext: 'We read books',
    revocationMode: 'open',
    expirationDays: 30,
    version: 4,
    ...overrides,
  }
}

function privateDetail(overrides: Partial<GroupDetail> = {}): GroupDetail {
  return {
    groupId: 'priv-1',
    visibility: 'private',
    role: 'admin',
    generation: 0,
    nameGeneration: 0,
    nameCiphertext: NAME_CT,
    descriptionCiphertext: DESC_CT,
    wrappedGroupKey: WRAPPED_KEY,
    revocationMode: 'rotating',
    expirationDays: 30,
    version: 2,
    ...overrides,
  }
}

function loadDeps(
  detail: GroupDetail,
  overrides: Partial<LoadSettingsDeps> = {},
): LoadSettingsDeps {
  return {
    getGroup: vi.fn().mockResolvedValue(detail),
    decryptGroupNames: vi.fn().mockResolvedValue([{ name: 'Roof Group', description: 'The roof' }]),
    getCachedGroupName: vi.fn().mockReturnValue(null),
    setCachedGroupName: vi.fn(),
    userId: 'user-1',
    ...overrides,
  }
}

describe('loadGroupSettings', () => {
  it('returns a public group as plaintext without touching the worker', async () => {
    const deps = loadDeps(publicDetail())
    const result = await loadGroupSettings(deps, 'pub-1')
    expect(result).toMatchObject({
      ok: true,
      view: { name: 'Book Club', description: 'We read books', nameStatus: 'plaintext' },
    })
    expect(deps.decryptGroupNames).not.toHaveBeenCalled()
  })

  it('decrypts a private group under nameGeneration and caches the result', async () => {
    const deps = loadDeps(privateDetail({ generation: 2, nameGeneration: 1 }))
    const result = await loadGroupSettings(deps, 'priv-1')
    expect(result).toMatchObject({
      ok: true,
      view: { name: 'Roof Group', nameStatus: 'decrypted' },
    })
    expect(deps.decryptGroupNames).toHaveBeenCalledWith({
      userId: 'user-1',
      groups: [expect.objectContaining({ generation: 2, nameGeneration: 1 })],
    })
    expect(deps.setCachedGroupName).toHaveBeenCalledWith(
      'user-1',
      'priv-1',
      1,
      'Roof Group',
      'The roof',
    )
  })

  it('serves a private group from cache without decrypting', async () => {
    const deps = loadDeps(privateDetail(), {
      getCachedGroupName: vi.fn().mockReturnValue({ name: 'Cached', description: 'C' }),
    })
    const result = await loadGroupSettings(deps, 'priv-1')
    expect(result).toMatchObject({ ok: true, view: { name: 'Cached', nameStatus: 'decrypted' } })
    expect(deps.decryptGroupNames).not.toHaveBeenCalled()
  })

  it('reports coldKeys, keeping the rest of the settings, when the worker has no keys', async () => {
    const deps = loadDeps(privateDetail(), {
      decryptGroupNames: vi.fn().mockRejectedValue(new Error('worker: no live keys cached')),
    })
    const result = await loadGroupSettings(deps, 'priv-1')
    expect(result).toMatchObject({
      ok: true,
      view: { name: null, nameStatus: 'coldKeys', detail: { revocationMode: 'rotating' } },
    })
    expect(deps.setCachedGroupName).not.toHaveBeenCalled()
  })

  it('reports unreadable, and does not cache, when this group fails to decrypt', async () => {
    const deps = loadDeps(privateDetail(), {
      decryptGroupNames: vi.fn().mockResolvedValue([{ name: null, description: null }]),
    })
    const result = await loadGroupSettings(deps, 'priv-1')
    expect(result).toMatchObject({ ok: true, view: { nameStatus: 'unreadable' } })
    expect(deps.setCachedGroupName).not.toHaveBeenCalled()
  })

  it('maps 404, 401 and everything else to distinct failures', async () => {
    const fail = (err: unknown) =>
      loadGroupSettings(loadDeps(publicDetail(), { getGroup: vi.fn().mockRejectedValue(err) }), 'x')
    expect(await fail(new ApiError(404, 'group not found'))).toEqual({
      ok: false,
      kind: 'notFound',
    })
    expect(await fail(new ApiError(401, 'nope'))).toEqual({ ok: false, kind: 'authRequired' })
    expect(await fail(new Error('network'))).toEqual({ ok: false, kind: 'failed' })
  })
})

function view(detail: GroupDetail, name: string, description: string): SettingsView {
  return {
    detail,
    name,
    description,
    nameStatus: detail.visibility === 'public' ? 'plaintext' : 'decrypted',
  }
}

function saveDeps(overrides: Partial<SaveSettingsDeps> = {}): SaveSettingsDeps {
  return {
    updateGroup: vi.fn().mockResolvedValue({ version: 5 }),
    encryptGroupText: vi
      .fn()
      .mockResolvedValue({ nameCiphertext: NEW_NAME_CT, descriptionCiphertext: NEW_DESC_CT }),
    setCachedGroupName: vi.fn(),
    userId: 'user-1',
    ...overrides,
  }
}

const FORM = { name: 'New Name', description: 'New description', expirationDays: 90 }

describe('saveGroupSettings', () => {
  it('sends plaintext for a public group, echoing the loaded version', async () => {
    const deps = saveDeps()
    const result = await saveGroupSettings(deps, view(publicDetail(), 'Book Club', 'x'), FORM)
    expect(result).toEqual({ ok: true, version: 5 })
    expect(deps.updateGroup).toHaveBeenCalledWith('pub-1', {
      version: 4,
      namePlaintext: 'New Name',
      descriptionPlaintext: 'New description',
      expirationDays: 90,
    })
    expect(deps.encryptGroupText).not.toHaveBeenCalled()
  })

  it('seals a private group at the caller generation and refreshes the cache', async () => {
    const deps = saveDeps()
    const detail = privateDetail({ generation: 3, nameGeneration: 1 })
    const result = await saveGroupSettings(deps, view(detail, 'Old', 'Old'), FORM)
    expect(result).toEqual({ ok: true, version: 5 })
    expect(deps.encryptGroupText).toHaveBeenCalledWith(
      expect.objectContaining({ generation: 3, nameGeneration: 3, name: 'New Name' }),
    )
    expect(deps.updateGroup).toHaveBeenCalledWith('priv-1', {
      version: 2,
      nameCiphertext: NEW_NAME_CT,
      descriptionCiphertext: NEW_DESC_CT,
      nameGeneration: 3,
      expirationDays: 90,
    })
    // Without this the list screen would keep showing the OLD cached name.
    expect(deps.setCachedGroupName).toHaveBeenCalledWith(
      'user-1',
      'priv-1',
      3,
      'New Name',
      'New description',
    )
  })

  it('does not send anything, and reports coldKeys, when the worker has no keys', async () => {
    const deps = saveDeps({
      encryptGroupText: vi.fn().mockRejectedValue(new Error('worker: no live keys cached')),
    })
    const result = await saveGroupSettings(deps, view(privateDetail(), 'a', 'b'), FORM)
    expect(result).toEqual({ ok: false, kind: 'coldKeys' })
    expect(deps.updateGroup).not.toHaveBeenCalled()
  })

  it('does not send anything when encryption fails for another reason', async () => {
    const deps = saveDeps({ encryptGroupText: vi.fn().mockRejectedValue(new Error('bad wrap')) })
    const result = await saveGroupSettings(deps, view(privateDetail(), 'a', 'b'), FORM)
    expect(result).toMatchObject({ ok: false, kind: 'rejected' })
    expect(deps.updateGroup).not.toHaveBeenCalled()
  })

  it.each([
    [new ApiError(409, 'stale', 'version_conflict'), { kind: 'versionConflict' }],
    [new ApiError(403, 'no'), { kind: 'forbidden' }],
    [new ApiError(401, 'no'), { kind: 'authRequired' }],
    [new ApiError(404, 'gone'), { kind: 'notFound' }],
    [
      new ApiError(400, 'namePlaintext: too long'),
      { kind: 'rejected', message: 'namePlaintext: too long' },
    ],
    [new ApiError(500, 'boom'), { kind: 'ambiguous' }],
    [new Error('network down'), { kind: 'ambiguous' }],
  ])('classifies %s', async (err, expected) => {
    const deps = saveDeps({ updateGroup: vi.fn().mockRejectedValue(err) })
    const result = await saveGroupSettings(deps, view(publicDetail(), 'a', 'b'), FORM)
    expect(result).toMatchObject({ ok: false, ...expected })
    expect(deps.setCachedGroupName).not.toHaveBeenCalled()
  })

  it('treats a 409 without the version_conflict code as a rejection, not a retry', async () => {
    const deps = saveDeps({ updateGroup: vi.fn().mockRejectedValue(new ApiError(409, 'other')) })
    const result = await saveGroupSettings(deps, view(publicDetail(), 'a', 'b'), FORM)
    expect(result).toMatchObject({ ok: false, kind: 'rejected' })
  })
})
