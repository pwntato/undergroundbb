// The async bodies behind GroupSettingsScreen -- issue #36. Plain functions
// that take their network/worker/cache calls as arguments, the same split
// runListGroups.ts and runCreateGroup.ts make from their own screens, so
// this is unit-testable under vitest's node environment with no jsdom or
// real worker.

import { ApiError } from '@/lib/api/auth'
import type { GroupDetail, UpdateGroupRequest } from '@/lib/api/groups'
import { nameStamp } from '@/lib/groups/groupNameCache'
import { isLiveKeysError } from './runListGroups'

type Blob = { nonce: string; ciphertext: string }

/** A group ready to render: the server's detail plus its name/description resolved to text. */
export interface SettingsView {
  readonly detail: GroupDetail
  readonly name: string | null
  readonly description: string | null
  /**
   * 'plaintext' for a public group; for a private one 'decrypted', or
   * 'coldKeys' (the crypto worker holds no keys -- e.g. the tab was
   * reloaded since login; logging in again fixes it) or 'unreadable' (keys
   * were live but this group's own ciphertext would not decrypt).
   */
  readonly nameStatus: 'plaintext' | 'decrypted' | 'unreadable' | 'coldKeys'
}

export interface LoadSettingsDeps {
  readonly getGroup: (groupId: string) => Promise<GroupDetail>
  readonly decryptGroupNames: (req: {
    readonly userId: string
    readonly groups: readonly {
      readonly groupId: string
      readonly generation: number
      readonly nameGeneration: number
      readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
      readonly nameCiphertext: Blob
      readonly descriptionCiphertext: Blob
      readonly chain?: readonly {
        readonly generation: number
        readonly wrapped: { nonce: string; ciphertext: string }
      }[]
    }[]
  }) => Promise<readonly { name: string | null; description: string | null }[]>
  /**
   * The GENKEY# links the name needs when it was sealed under an older
   * generation than the caller's own (fetchNameChain). Optional only so a
   * caller with no network can skip the walk; the name then reads as unreadable.
   */
  readonly getNameChain?: (
    groupId: string,
    nameGeneration: number,
    generation: number,
  ) => Promise<
    | readonly {
        readonly generation: number
        readonly wrapped: { nonce: string; ciphertext: string }
      }[]
    | undefined
  >
  readonly getCachedGroupName: (
    userId: string,
    groupId: string,
    generation: number,
    stamp: string,
  ) => { name: string | null; description: string | null } | null
  readonly setCachedGroupName: (
    userId: string,
    groupId: string,
    generation: number,
    stamp: string,
    name: string | null,
    description: string | null,
  ) => void
  readonly userId: string
}

export type LoadSettingsResult =
  | { readonly ok: true; readonly view: SettingsView }
  // 404: no such group, or a private group the caller is not in -- the
  // server deliberately does not distinguish them, and neither does this.
  | { readonly ok: false; readonly kind: 'notFound' | 'authRequired' | 'failed' }

/**
 * Fetches a group's detail and resolves its name/description. Never throws:
 * a cold-keys or per-group decrypt failure becomes a nameStatus, so the
 * settings that need no keys (revocation mode, expiration) still render.
 */
export async function loadGroupSettings(
  deps: LoadSettingsDeps,
  groupId: string,
): Promise<LoadSettingsResult> {
  let detail: GroupDetail
  try {
    detail = await deps.getGroup(groupId)
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) {
      return { ok: false, kind: 'notFound' }
    }
    if (err instanceof ApiError && err.status === 401) {
      return { ok: false, kind: 'authRequired' }
    }
    return { ok: false, kind: 'failed' }
  }

  if (detail.visibility === 'public') {
    return {
      ok: true,
      view: {
        detail,
        name: detail.namePlaintext ?? '',
        description: detail.descriptionPlaintext ?? '',
        nameStatus: 'plaintext',
      },
    }
  }

  const unreadable: SettingsView = {
    detail,
    name: null,
    description: null,
    nameStatus: 'unreadable',
  }
  if (!detail.nameCiphertext || !detail.descriptionCiphertext || !detail.wrappedGroupKey) {
    return { ok: true, view: unreadable }
  }

  // Keyed on the ciphertext as well as the generation: an edit keeps the
  // generation, so without the stamp a cache hit here would hand back an
  // older name under the newer version, and a save would silently revert
  // another admin's rename (PR #151 review).
  const stamp = nameStamp(detail.nameCiphertext, detail.descriptionCiphertext)
  const cached = deps.getCachedGroupName(deps.userId, groupId, detail.nameGeneration, stamp)
  if (cached) {
    return {
      ok: true,
      view: {
        detail,
        name: cached.name,
        description: cached.description,
        nameStatus: cached.name === null ? 'unreadable' : 'decrypted',
      },
    }
  }

  try {
    const chain =
      deps.getNameChain === undefined || detail.nameGeneration >= detail.generation
        ? undefined
        : await deps.getNameChain(groupId, detail.nameGeneration, detail.generation)
    const [result] = await deps.decryptGroupNames({
      userId: deps.userId,
      groups: [
        {
          ...(chain !== undefined && { chain }),
          groupId,
          generation: detail.generation,
          nameGeneration: detail.nameGeneration,
          wrappedGroupKey: detail.wrappedGroupKey,
          nameCiphertext: detail.nameCiphertext,
          descriptionCiphertext: detail.descriptionCiphertext,
        },
      ],
    })
    if (!result || result.name === null) {
      return { ok: true, view: unreadable }
    }
    deps.setCachedGroupName(
      deps.userId,
      groupId,
      detail.nameGeneration,
      stamp,
      result.name,
      result.description,
    )
    return {
      ok: true,
      view: { detail, name: result.name, description: result.description, nameStatus: 'decrypted' },
    }
  } catch (err) {
    if (isLiveKeysError(err)) {
      return { ok: true, view: { ...unreadable, nameStatus: 'coldKeys' } }
    }
    return { ok: false, kind: 'failed' }
  }
}

export interface SettingsForm {
  readonly name: string
  readonly description: string
  /** 0 means "never expire" -- the server rejects it where the deployment forbids it. */
  readonly expirationDays: number
}

export interface SaveSettingsDeps {
  readonly updateGroup: (groupId: string, req: UpdateGroupRequest) => Promise<{ version: number }>
  readonly encryptGroupText: (req: {
    readonly userId: string
    readonly groupId: string
    readonly generation: number
    readonly nameGeneration: number
    readonly wrappedGroupKey: { ephemeralPub: string; nonce: string; ciphertext: string }
    readonly name: string
    readonly description: string
  }) => Promise<{ nameCiphertext: Blob; descriptionCiphertext: Blob }>
  readonly setCachedGroupName: LoadSettingsDeps['setCachedGroupName']
  readonly userId: string
}

export type SaveSettingsResult =
  | { readonly ok: true; readonly version: number }
  // 409 version_conflict: another admin saved first. Reload and reapply; a
  // lost-response retry of the caller's OWN committed save lands here too
  // (its version is now stale), and reloading shows their values in place.
  | { readonly ok: false; readonly kind: 'versionConflict' }
  | { readonly ok: false; readonly kind: 'forbidden' | 'authRequired' | 'coldKeys' | 'notFound' }
  // A 4xx validation failure, with the server's own message.
  | { readonly ok: false; readonly kind: 'rejected'; readonly message: string }
  // Network failure or 5xx: the save may or may not have committed.
  | { readonly ok: false; readonly kind: 'ambiguous' }

/**
 * Seals (private groups only) and submits an edit. On success, refreshes the
 * name cache with the plaintext just saved: the list screen would otherwise
 * keep showing the OLD cached name, since an edit does not change the
 * cache's generation key.
 */
export async function saveGroupSettings(
  deps: SaveSettingsDeps,
  view: SettingsView,
  form: SettingsForm,
): Promise<SaveSettingsResult> {
  const { detail } = view
  const base = { version: detail.version, expirationDays: form.expirationDays }

  let req: UpdateGroupRequest
  // Stamp of the ciphertext this save writes, for the post-save cache entry.
  let savedStamp = ''
  if (detail.visibility === 'public') {
    req = { ...base, namePlaintext: form.name, descriptionPlaintext: form.description }
  } else {
    if (!detail.wrappedGroupKey) {
      return { ok: false, kind: 'coldKeys' }
    }
    try {
      // The server requires nameGeneration to equal the caller's own
      // generation (handlers.updateGroup), so both are detail.generation.
      const sealed = await deps.encryptGroupText({
        userId: deps.userId,
        groupId: detail.groupId,
        generation: detail.generation,
        nameGeneration: detail.generation,
        wrappedGroupKey: detail.wrappedGroupKey,
        name: form.name,
        description: form.description,
      })
      savedStamp = nameStamp(sealed.nameCiphertext, sealed.descriptionCiphertext)
      req = {
        ...base,
        nameCiphertext: sealed.nameCiphertext,
        descriptionCiphertext: sealed.descriptionCiphertext,
        nameGeneration: detail.generation,
      }
    } catch (err) {
      // A worker call, not a request: nothing was sent.
      return isLiveKeysError(err)
        ? { ok: false, kind: 'coldKeys' }
        : { ok: false, kind: 'rejected', message: "Couldn't encrypt your changes. Try again." }
    }
  }

  try {
    const { version } = await deps.updateGroup(detail.groupId, req)
    if (detail.visibility === 'private') {
      deps.setCachedGroupName(
        deps.userId,
        detail.groupId,
        detail.generation,
        savedStamp,
        form.name,
        form.description,
      )
    }
    return { ok: true, version }
  } catch (err) {
    if (err instanceof ApiError) {
      if (err.status === 409 && err.code === 'version_conflict') {
        return { ok: false, kind: 'versionConflict' }
      }
      if (err.status === 401) {
        return { ok: false, kind: 'authRequired' }
      }
      if (err.status === 403) {
        return { ok: false, kind: 'forbidden' }
      }
      if (err.status === 404) {
        return { ok: false, kind: 'notFound' }
      }
      if (err.status < 500) {
        return { ok: false, kind: 'rejected', message: err.message }
      }
    }
    return { ok: false, kind: 'ambiguous' }
  }
}
