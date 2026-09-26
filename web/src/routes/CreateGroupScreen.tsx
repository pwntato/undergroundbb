// #34: create-group screen. Wrapped by RequireAuth in App.tsx (baseline
// session check, per that file's own guidance: this screen has a real
// authenticated request -- POST /api/groups -- to piggyback on for a
// session that expires mid-visit, the same reasoning ChangePasswordScreen
// gives for doing its own bootstrap check rather than relying only on
// RequireAuth).
//
// Owns groupId and group-key generation itself, ahead of calling
// runCreateGroup -- see that file's own header comment for why: a private
// group's name/description are encrypted here, under an AAD
// (groupNameAAD) that binds the group id, so the group id has to exist
// before encryption can happen, which is before runCreateGroup (which only
// signs and submits an already-fully-formed request) is ever called.
//
// Caches the exact groupId/group key/form values an ambiguous failure used,
// in this component's own state (`resume`), and reuses them verbatim on a
// matching retry -- the same PR #133-round-1 reasoning runSignup.ts's
// PendingSignup exists for, applied here instead of inside runCreateGroup
// itself (see that file's header comment on why the split moved).

import { useState } from 'react'
import { useNavigate } from 'react-router'
import { createGroup } from '@/lib/api/groups'
import { encrypt } from '@/lib/crypto/aesgcm'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import { groupNameAAD } from '@/lib/crypto/group'
import { generateUUID } from '@/lib/crypto/uuid'
import { signGroupCreation } from '@/lib/crypto/worker-client'
import { useSession } from '@/lib/session/useSession'
import { CreateGroupFormStep, type GroupFormValues } from './CreateGroupFormStep'
import { runCreateGroup, type CreateGroupErrorKind, type GroupFormInput } from './runCreateGroup'

const UNREACHABLE_ERROR = "Couldn't reach the server. Try again."
const AMBIGUOUS_ERROR =
  "We couldn't confirm whether your group was created. Try again — resubmitting is safe."
const AUTH_REQUIRED_ERROR = 'Your session has expired. Log in again and retry.'
// Distinct from AUTH_REQUIRED_ERROR: the session cookie can still be valid
// (RequireAuth and even a fresh createGroup call would both pass) while the
// crypto worker's own cached signing/wrapping keys are cold -- e.g. this tab
// was reloaded since login, which resets worker.ts's module-scope liveKeys
// along with everything else. See worker.ts's own signGroupCreation for the
// exact thrown error this message covers -- it surfaces here as a plain
// Error (not an ApiError), so it is classified 'definitelyUncommitted' by
// runCreateGroup but shown with this more specific, actionable copy instead
// of UNREACHABLE_ERROR.
const KEYS_NOT_LIVE_ERROR = 'Log in again on this tab before creating a group.'

function errorMessageFor(kind: CreateGroupErrorKind, error: unknown): string {
  switch (kind) {
    case 'definitelyUncommitted':
      return isLiveKeysError(error) ? KEYS_NOT_LIVE_ERROR : UNREACHABLE_ERROR
    case 'ambiguous':
      return AMBIGUOUS_ERROR
    case 'authRequired':
      return AUTH_REQUIRED_ERROR
  }
}

/** See worker.ts's signGroupCreation: the exact message it throws when liveKeys is unset or belongs to a different account. */
function isLiveKeysError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message.includes('no live keys cached') ||
      error.message.includes('cached keys belong to a different account'))
  )
}

/** One create-group attempt's generated material, kept in state so an ambiguous failure's retry can reuse it verbatim rather than regenerating -- see this file's own header comment. */
interface PendingAttempt {
  readonly groupId: string
  readonly groupKeyB64: string
  readonly values: GroupFormValues
  readonly form: GroupFormInput
}

export function CreateGroupScreen() {
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState<PendingAttempt | undefined>(undefined)
  const navigate = useNavigate()
  const session = useSession()

  const handleSubmit = (values: GroupFormValues) => {
    if (session.userId === null) {
      // Unreachable via App.tsx's RequireAuth wrapping -- guarded anyway,
      // the same defensiveness requireSession's own handlers apply
      // server-side.
      setError(AUTH_REQUIRED_ERROR)
      return
    }
    const userId = session.userId

    setError(null)
    setSubmitting(true)

    void (async () => {
      const resuming = pending !== undefined && formValuesEqual(pending.values, values)

      const groupId = resuming ? pending.groupId : generateUUID()
      const groupKeyB64 = resuming
        ? pending.groupKeyB64
        : bytesToBase64(crypto.getRandomValues(new Uint8Array(32)))
      const form = resuming
        ? pending.form
        : await buildFormInput(values, groupId, base64ToBytes(groupKeyB64))

      const result = await runCreateGroup(
        { signGroupCreation, createGroup, userId },
        groupId,
        groupKeyB64,
        form,
      )

      if (!result.ok) {
        setPending({ groupId, groupKeyB64, values, form })
        setError(errorMessageFor(result.kind, result.error))
        setSubmitting(false)
        return
      }

      setPending(undefined)
      setSubmitting(false)
      // #35 (list groups) is what will actually show the new group; for now
      // this just returns Home, matching Home.tsx's own placeholder state.
      navigate('/', { replace: true })
    })()
  }

  return <CreateGroupFormStep onSubmit={handleSubmit} error={submitting ? null : error} />
}

/** Structural comparison of the plaintext form values a pending attempt was built from -- deliberately excludes derived ciphertext, which is always freshly re-encrypted under a fresh nonce even for identical plaintext (see buildFormInput). */
function formValuesEqual(a: GroupFormValues, b: GroupFormValues): boolean {
  return (
    a.visibility === b.visibility &&
    a.name === b.name &&
    a.description === b.description &&
    a.revocationMode === b.revocationMode &&
    a.expirationDays === b.expirationDays
  )
}

/** Builds a GroupFormInput from GroupFormValues, encrypting name/description under groupKey (AAD-bound to groupId) for a private group. */
async function buildFormInput(
  values: GroupFormValues,
  groupId: string,
  groupKey: Uint8Array,
): Promise<GroupFormInput> {
  if (values.visibility === 'public') {
    return {
      visibility: 'public',
      namePlaintext: values.name,
      descriptionPlaintext: values.description,
      revocationMode: values.revocationMode,
      expirationDays: values.expirationDays,
    }
  }

  // Private: name/description are encrypted under the group key at
  // Generation 0 -- AAD is groupNameAAD(groupId, field, 0), per
  // docs/DESIGN.md's AAD table, "Group name/description."
  const encoder = new TextEncoder()
  const { nonce: nameNonce, ciphertext: nameCiphertext } = await encrypt(
    groupKey,
    encoder.encode(values.name),
    groupNameAAD(groupId, 'NAME', 0),
  )
  const { nonce: descriptionNonce, ciphertext: descriptionCiphertext } = await encrypt(
    groupKey,
    encoder.encode(values.description),
    groupNameAAD(groupId, 'DESC', 0),
  )

  return {
    visibility: 'private',
    nameCiphertext: { nonce: bytesToBase64(nameNonce), ciphertext: bytesToBase64(nameCiphertext) },
    descriptionCiphertext: {
      nonce: bytesToBase64(descriptionNonce),
      ciphertext: bytesToBase64(descriptionCiphertext),
    },
    revocationMode: values.revocationMode,
    expirationDays: values.expirationDays,
  }
}
