// #38: create-invite screen. Wrapped by RequireAuth in App.tsx (baseline
// session check; the server-side 403 for a non-admin/ambassador is this
// screen's own real authorization check, the same split CreateGroupScreen
// gives for its own RequireAuth wrapping).
//
// Owns inviteId generation itself, ahead of calling runCreateInvite -- see
// that file's own header comment for why: the signed payload binds the
// invite id, so it has to exist before signing, which is before
// runCreateInvite (which only signs and submits an already-chosen id) is
// ever called. Caches the exact inviteId/expiresAt an ambiguous failure
// used, in this component's own state (`pending`), and reuses it verbatim
// on a matching retry -- the same PR #133/#142-lineage reasoning
// CreateGroupScreen's own header comment describes, applied here since
// there is at least an inviteId (even without a group key) that a retry
// must not silently regenerate after an actually-committed first attempt.

import { useState, type FormEvent } from 'react'
import { useParams } from 'react-router'
import { createInvite } from '@/lib/api/invites'
import { generateUUID } from '@/lib/crypto/uuid'
import { signInviteCreation } from '@/lib/crypto/worker-client'
import { useSession } from '@/lib/session/useSession'
import {
  runCreateInvite,
  type CreateInviteErrorKind,
  type CreateInviteResult,
} from './runCreateInvite'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

const UNREACHABLE_ERROR = "Couldn't reach the server. Try again."
const AMBIGUOUS_ERROR =
  "We couldn't confirm whether your invite was created. Try again — resubmitting is safe."
const AUTH_REQUIRED_ERROR = 'Your session has expired. Log in again and retry.'
const FORBIDDEN_ERROR = 'You must be an admin or ambassador of this group to create an invite.'

function errorMessageFor(kind: CreateInviteErrorKind): string {
  switch (kind) {
    case 'definitelyUncommitted':
      return UNREACHABLE_ERROR
    case 'ambiguous':
      return AMBIGUOUS_ERROR
    case 'authRequired':
      return AUTH_REQUIRED_ERROR
    case 'forbidden':
      return FORBIDDEN_ERROR
  }
}

/**
 * Reports whether err is worker.ts's signInviteCreation throwing because
 * liveKeys is cold -- see CreateGroupScreen's own isLiveKeysError for the
 * identical reasoning. This screen does not offer an inline re-auth step
 * the way CreateGroupScreen does (ReauthenticateStep) -- a plain error
 * asking the admin to log in again is enough here, since losing a
 * half-typed invite form (just an expiry choice) costs far less than
 * CreateGroupScreen losing a name/description the user typed.
 */
function isLiveKeysError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message.includes('no live keys cached') ||
      error.message.includes('cached keys belong to a different account'))
  )
}

const EXPIRY_OPTIONS = [
  { label: '1 day', hours: 24 },
  { label: '7 days', hours: 24 * 7 },
  { label: '30 days', hours: 24 * 30 },
] as const

interface PendingAttempt {
  readonly inviteId: string
  readonly expiresAt: string
}

export function CreateInviteScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  const [expiryHours, setExpiryHours] = useState<number>(EXPIRY_OPTIONS[1].hours)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [pending, setPending] = useState<PendingAttempt | undefined>(undefined)
  const [result, setResult] = useState<Extract<CreateInviteResult, { ok: true }> | undefined>(
    undefined,
  )
  const session = useSession()

  if (groupId === undefined) {
    // Unreachable via App.tsx's own route param, guarded anyway.
    return (
      <Alert variant="destructive">
        <AlertDescription>Missing group id.</AlertDescription>
      </Alert>
    )
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (session.userId === null) {
      setError(AUTH_REQUIRED_ERROR)
      return
    }
    const userId = session.userId

    setError(null)
    setSubmitting(true)

    void (async () => {
      const resuming = pending !== undefined
      const inviteId = resuming ? pending.inviteId : generateUUID()
      const expiresAt = resuming
        ? pending.expiresAt
        : new Date(Date.now() + expiryHours * 60 * 60 * 1000).toISOString()

      const outcome = await runCreateInvite(
        { signInviteCreation, createInvite, userId },
        inviteId,
        groupId,
        expiresAt,
      )

      setSubmitting(false)
      if (!outcome.ok) {
        if (outcome.kind === 'definitelyUncommitted' && isLiveKeysError(outcome.error)) {
          setError(AUTH_REQUIRED_ERROR)
          return
        }
        if (outcome.kind === 'forbidden') {
          // Not retriable by resubmitting -- clear any cached attempt so a
          // later, correctly-authorized retry starts fresh.
          setPending(undefined)
          setError(errorMessageFor(outcome.kind))
          return
        }
        setPending({ inviteId, expiresAt })
        setError(errorMessageFor(outcome.kind))
        return
      }

      setPending(undefined)
      setResult(outcome)
    })()
  }

  if (result !== undefined) {
    return (
      <InviteCreatedStep
        inviteId={result.response.inviteId}
        inviterFingerprint={result.inviterFingerprint}
      />
    )
  }

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm flex-col gap-4">
      <h1 className="text-lg font-semibold">Invite someone</h1>
      {error !== null && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="flex flex-col gap-2">
        <Label htmlFor="expiry">Link expires in</Label>
        <select
          id="expiry"
          className="border-input bg-transparent flex h-9 w-full rounded-md border px-3 py-1 text-sm shadow-xs"
          value={expiryHours}
          onChange={(e) => {
            setExpiryHours(Number(e.target.value))
          }}
        >
          {EXPIRY_OPTIONS.map((opt) => (
            <option key={opt.hours} value={opt.hours}>
              {opt.label}
            </option>
          ))}
        </select>
      </div>
      <Button type="submit" disabled={submitting}>
        {submitting ? 'Creating…' : 'Create invite'}
      </Button>
    </form>
  )
}

/**
 * Shown once an invite is successfully created -- displays the link
 * (embedding inviterFingerprint in the URL FRAGMENT, per docs/DESIGN.md:
 * "the generated link carries the inviter's key fingerprint in the URL
 * fragment, which browsers never transmit") and the fingerprint itself in
 * plain text, "while the user is paying attention" (issue #38's own
 * wording) -- this is the one moment the inviter is looking at this
 * screen specifically to hand the link to someone, so it is also the
 * moment they're most likely to actually read and relay the fingerprint
 * out of band if they choose to.
 */
function InviteCreatedStep({
  inviteId,
  inviterFingerprint,
}: {
  inviteId: string
  inviterFingerprint: string
}) {
  const link = `${window.location.origin}/invites/${inviteId}#${inviterFingerprint}`
  return (
    <div className="flex w-full max-w-sm flex-col gap-4">
      <h1 className="text-lg font-semibold">Invite created</h1>
      <p className="text-sm text-muted-foreground">
        Share this link with the person you're inviting. Anyone who opens it can join once they
        accept.
      </p>
      <div className="flex flex-col gap-2">
        <Label htmlFor="invite-link">Invite link</Label>
        <Input id="invite-link" readOnly value={link} onFocus={(e) => e.currentTarget.select()} />
      </div>
      <div className="flex flex-col gap-2">
        <Label>Your fingerprint</Label>
        <p className="font-mono text-sm break-all">{inviterFingerprint}</p>
        <p className="text-xs text-muted-foreground">
          Anyone who opens the link can compare this against what their client shows to confirm
          they're really talking to you.
        </p>
      </div>
    </div>
  )
}
