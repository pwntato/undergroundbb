// The loop an edit of a post or a comment runs, shared by runEditComment.ts and
// runEditPost.ts -- #45. It knows nothing about what is being edited: the caller
// says how to seal and how to send, and which 409 code means "deleted meanwhile".
//
// What an answer means:
//
//   - `conflict_retry`: another write to the same item got there first. The edit
//     has not landed, and the same bytes are sent again (the write is conditional
//     on the edition the server reads, so a retry sees the new one).
//   - no answer / 5xx: the edit may or may not have landed. The caller keeps
//     `sealed` and sends exactly those bytes next time; the server answers 200 for
//     bytes it already stores, even when the signing day has passed.
//   - `nonce_reused`, `generation_stale`, `membership_changed`, `key_epoch_stale`:
//     the bytes cannot be accepted as they are; seal again.
//   - the gone code: someone deleted it meanwhile; nothing to retry.

import { ApiError } from '@/lib/api/auth'

/** Sends the same bytes again at most this many times after a write collision. */
export const MAX_EDIT_RETRIES = 3
/** Seals again at most this many times for one press. */
export const MAX_EDIT_RESEALS = 2

export type EditFailure =
  | 'authRequired'
  /** The post or the group is gone for this member, e.g. the post was deleted. */
  | 'notFound'
  | 'behind'
  | 'dormant'
  | 'coldKeys'
  | 'unreadable'
  | 'failed'
  /** The item was deleted while it was being edited. */
  | 'gone'
  /** Other writers kept colliding with this one, or the key kept moving. */
  | 'busy'
  /** The server refused the signing day: this device's clock is off. */
  | 'clockSkew'
  | 'rejected'
  /** No answer: the edit may have landed. Send `sealed` again unchanged. */
  | 'ambiguous'

export type EditResult<S> =
  | { readonly ok: true }
  | {
      readonly ok: false
      readonly kind: EditFailure
      readonly message?: string
      /** Set only for 'ambiguous'. */
      readonly sealed?: S
    }

type Step = 'retry' | 'reseal' | { readonly fail: EditFailure; readonly message?: string }

/** What an error from an edit request means; `goneCode` is the 409 code for a deleted item. */
export function classifyEditError(err: unknown, goneCode: string): Step | 'ambiguous' {
  if (!(err instanceof ApiError) || err.status >= 500) return 'ambiguous'
  if (err.status === 401) return { fail: 'authRequired' }
  if (err.status === 404) return { fail: 'notFound' }
  if (err.status === 409) {
    switch (err.code) {
      case 'conflict_retry':
        return 'retry'
      case 'generation_stale':
      case 'membership_changed':
      case 'key_epoch_stale':
        return 'reseal'
      case goneCode:
        return { fail: 'gone' }
      case 'member_behind':
        return { fail: 'behind' }
      case 'member_dormant':
        return { fail: 'dormant' }
    }
  }
  if (err.status === 400 && err.code === 'nonce_reused') return 'reseal'
  if (err.status === 400 && err.code === 'clock_skew') return { fail: 'clockSkew' }
  return { fail: 'rejected', message: err.message }
}

/**
 * Seals and sends, following the rules above. `seal` loads whatever sealing needs
 * and seals (or says why it could not); `send` sends one sealed edition. With
 * `resend` (an edit a send left unanswered) the first attempt sends those exact
 * bytes instead of sealing. Never throws.
 */
export async function runEdit<S>(input: {
  readonly seal: () => Promise<
    { readonly ok: true; readonly sealed: S } | { readonly ok: false; readonly kind: EditFailure }
  >
  readonly send: (sealed: S) => Promise<unknown>
  readonly goneCode: string
  readonly resend?: S | undefined
}): Promise<EditResult<S>> {
  let pending = input.resend
  for (let reseals = 0; ; reseals++) {
    let sealed: S
    if (pending !== undefined) {
      sealed = pending
      pending = undefined
    } else {
      const made = await input.seal()
      if (!made.ok) return { ok: false, kind: made.kind }
      sealed = made.sealed
    }
    // The same bytes go again after a collision; only a new seal changes them.
    let step: Step = 'retry'
    for (let retries = 0; step === 'retry'; retries++) {
      try {
        await input.send(sealed)
        return { ok: true }
      } catch (err) {
        const next = classifyEditError(err, input.goneCode)
        if (next === 'ambiguous') return { ok: false, kind: 'ambiguous', sealed }
        step = next
        if (step === 'retry' && retries >= MAX_EDIT_RETRIES) return { ok: false, kind: 'busy' }
      }
    }
    if (step !== 'reseal') {
      return {
        ok: false,
        kind: step.fail,
        ...(step.message !== undefined && { message: step.message }),
      }
    }
    if (reseals >= MAX_EDIT_RESEALS) return { ok: false, kind: 'busy' }
  }
}
