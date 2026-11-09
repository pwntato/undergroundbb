// Saving the signed-in user's bio (#75): the decision logic behind the profile
// page's Save button, as a plain function over an injected call so it is
// tested without a screen.

import { ApiError } from '@/lib/api/auth'
import { MAX_BIO_CHARS } from '@/lib/api/users'
import { bioFits } from './profileView'

export type SaveBioResult =
  | { readonly ok: true; readonly bio: string }
  | {
      readonly ok: false
      readonly kind: 'tooLong' | 'rejected' | 'authRequired' | 'notFound' | 'failed'
    }

export const SAVE_BIO_ERRORS: Record<Exclude<SaveBioResult, { ok: true }>['kind'], string> = {
  tooLong: `A bio is at most ${String(MAX_BIO_CHARS)} characters.`,
  rejected: "That text can't be saved. Remove any unusual control characters.",
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'This account no longer exists.',
  failed: "Couldn't save your bio. Try again.",
}

export async function saveBio(
  deps: { readonly putBio: (bio: string) => Promise<string> },
  draft: string,
): Promise<SaveBioResult> {
  if (!bioFits(draft)) {
    return { ok: false, kind: 'tooLong' }
  }
  try {
    return { ok: true, bio: await deps.putBio(draft) }
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 401) return { ok: false, kind: 'authRequired' }
      if (e.status === 404) return { ok: false, kind: 'notFound' }
      if (e.status === 400) return { ok: false, kind: 'rejected' }
    }
    return { ok: false, kind: 'failed' }
  }
}
