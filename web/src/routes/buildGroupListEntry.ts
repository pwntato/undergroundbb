import type { GroupListEntry } from '@/lib/api/groups'
import type { CreateGroupResult, GroupFormInput } from './runCreateGroup'

/**
 * Builds the GroupListEntry-shaped object passed to Home via router state
 * (newGroupNavigationState.ts) -- everything a GET /api/groups response
 * would carry for this exact group, built from data this screen already
 * has: groupId, the request's own form (visibility + plaintext/ciphertext +
 * revocationMode -- expirationDays isn't part of GroupListEntry itself, so
 * it's not carried here; revocationMode only as noRotation), and
 * result.groupKeyWrapped from the just-completed signGroupCreation call.
 * The creator is always role "admin" at generation 0 -- CreateGroup's own
 * Go side writes the creator's MEMBER# item with exactly those values (see
 * db.CreateGroup), so this isn't a guess.
 */
export function buildGroupListEntry(
  groupId: string,
  form: GroupFormInput,
  result: Extract<CreateGroupResult, { ok: true }>,
): GroupListEntry {
  if (form.visibility === 'public') {
    return {
      groupId,
      visibility: 'public',
      role: 'admin',
      generation: 0,
      noRotation: true,
      nameGeneration: 0,
      ...(form.namePlaintext !== undefined && { namePlaintext: form.namePlaintext }),
      ...(form.descriptionPlaintext !== undefined && {
        descriptionPlaintext: form.descriptionPlaintext,
      }),
    }
  }
  return {
    groupId,
    visibility: 'private',
    role: 'admin',
    generation: 0,
    noRotation: form.revocationMode === 'open',
    nameGeneration: 0,
    ...(form.nameCiphertext !== undefined && { nameCiphertext: form.nameCiphertext }),
    ...(form.descriptionCiphertext !== undefined && {
      descriptionCiphertext: form.descriptionCiphertext,
    }),
    wrappedGroupKey: result.groupKeyWrapped,
  }
}
