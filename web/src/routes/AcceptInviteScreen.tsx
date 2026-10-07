// #39: accept-invite screen. Deliberately NOT wrapped by RequireAuth in
// App.tsx -- an invite is a link handed to someone who may not have an
// account yet (models.Invite's own doc comment, Go side), so this screen
// must render and let GET /api/invites/{id} succeed for a fully logged-out
// visitor. Authentication is only required for the ACCEPT action itself
// (POST /api/invites/{id}/accept), checked inline below rather than at the
// route level.
//
// This screen does not implement a "log in, then come back and finish
// accepting automatically" redirect handoff -- no such mechanism exists
// yet anywhere in this app (SignupScreen/LoginScreen only ever navigate to
// a fixed destination), and building one is out of scope for this issue.
// An unauthenticated visitor is told to log in or sign up and then revisit
// this same link (which they still have -- it's an ordinary URL, and the
// fingerprint fragment survives a copy/paste or a bookmark) to finish
// accepting.
//
// Verification happens in two places, deliberately: verifyInvite (this
// screen's own client-side check, the moment the invite is fetched, NEVER
// trusting the server already checked anything) gates whether this screen
// shows "you've been invited" at all; runAcceptInvite (only reachable once
// authenticated) is what actually signs and submits step 2.

import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { acceptInvite, getInvite, type GetInviteResponse } from '@/lib/api/invites'
import { signInviteAcceptance } from '@/lib/crypto/worker-client'
import { useSession } from '@/lib/session/useSession'
import {
  runAcceptInvite,
  verifyInvite,
  type AcceptInviteErrorKind,
  type InviteVerificationFailure,
  inviteLoadFailure,
} from './runAcceptInvite'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

function verificationMessageFor(reason: InviteVerificationFailure): string {
  switch (reason) {
    case 'signatureInvalid':
      return "This invite link doesn't check out -- its signature isn't valid. Ask the person who invited you for a fresh link."
    case 'fingerprintMismatch':
      return "This invite's fingerprint doesn't match what your link says it should be. Don't accept it -- ask the person who invited you to confirm, or ask for a fresh link."
    case 'alreadyAccepted':
      return 'This invite has already been used.'
    case 'expired':
      return 'This invite has expired. Ask the person who invited you for a fresh link.'
  }
}

const AUTH_REQUIRED_ERROR = 'Your session has expired. Log in again and retry.'

/**
 * Reports whether err is worker.ts's signInviteAcceptance throwing because
 * liveKeys is cold -- e.g. this tab was reloaded since login, which resets
 * worker.ts's module-scope cache along with everything else, while the
 * session cookie stays valid. See CreateGroupScreen's own isLiveKeysError
 * for the identical reasoning; this screen shows a plain message pointing
 * at logging in again rather than an inline re-auth step, matching
 * CreateInviteScreen's own choice for the identical failure -- losing
 * nothing more than this button press costs far less than
 * CreateGroupScreen losing a half-typed form.
 */
function isLiveKeysError(error: unknown): boolean {
  return (
    error instanceof Error &&
    (error.message.includes('no live keys cached') ||
      error.message.includes('cached keys belong to a different account'))
  )
}

function acceptErrorMessageFor(kind: AcceptInviteErrorKind, error: unknown): string {
  switch (kind) {
    case 'definitelyUncommitted':
      return isLiveKeysError(error) ? AUTH_REQUIRED_ERROR : "Couldn't reach the server. Try again."
    case 'ambiguous':
      return "We couldn't confirm whether your acceptance went through. Try again -- resubmitting is safe."
    case 'authRequired':
      return AUTH_REQUIRED_ERROR
    case 'alreadyAccepted':
      return 'This invite has already been used -- possibly by you, in another tab.'
    case 'alreadyMember':
      return "You're already a member of this group."
    case 'expired':
      return 'This invite has expired.'
  }
}

/**
 * Splits the invite link's URL fragment into its two "." separated parts
 * -- see CreateInviteScreen.tsx's own doc comment on InviteCreatedStep for
 * the format this must match exactly. Returns both as undefined for a
 * link shared without a fragment at all (an older link format, or a copy
 * that dropped it) -- distinct from a fragment that has a fingerprint but
 * no macKey (malformed, treated the same as absent: there is no partial
 * fragment this app has ever produced).
 */
function parseInviteFragment(hash: string): {
  fingerprint: string | undefined
  macKey: string | undefined
} {
  if (hash.length <= 1) {
    return { fingerprint: undefined, macKey: undefined }
  }
  const [fingerprint, macKey] = hash.slice(1).split('.')
  if (fingerprint === undefined || macKey === undefined || macKey === '') {
    return { fingerprint: undefined, macKey: undefined }
  }
  return { fingerprint, macKey }
}

type LoadState =
  | { readonly kind: 'loading' }
  | { readonly kind: 'invalid'; readonly reason: InviteVerificationFailure }
  | { readonly kind: 'notFound' }
  | { readonly kind: 'networkError' }
  | {
      readonly kind: 'ready'
      readonly invite: GetInviteResponse
      readonly fingerprint: string
      readonly macKey: string | undefined
    }

export function AcceptInviteScreen() {
  const { inviteId } = useParams<{ inviteId: string }>()
  const session = useSession()
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const [accepting, setAccepting] = useState(false)
  const [acceptError, setAcceptError] = useState<string | null>(null)
  const [accepted, setAccepted] = useState(false)

  useEffect(() => {
    if (inviteId === undefined) {
      return
    }
    // The fragment is never sent to any server -- window.location.hash is
    // read directly, client-side only, per docs/DESIGN.md's own reasoning
    // for why the fingerprint (and, now, the invite MAC key) travels this
    // way at all. Format is "<fingerprint>.<inviteMACKey>" -- see
    // CreateInviteScreen.tsx's own doc comment on InviteCreatedStep for why
    // "." is a safe separator between the two alphabets.
    const { fingerprint: fragmentFingerprint, macKey: fragmentMACKey } = parseInviteFragment(
      window.location.hash,
    )

    let cancelled = false
    void (async () => {
      try {
        const invite = await getInvite(inviteId)
        if (cancelled) {
          return
        }
        const verification = verifyInvite(inviteId, invite, fragmentFingerprint)
        if (!verification.ok) {
          setState({ kind: 'invalid', reason: verification.reason })
          return
        }
        setState({
          kind: 'ready',
          invite,
          fingerprint: fragmentFingerprint ?? '',
          macKey: fragmentMACKey,
        })
      } catch (err) {
        if (cancelled) {
          return
        }
        const failure = inviteLoadFailure(err)
        setState(failure === 'expired' ? { kind: 'invalid', reason: 'expired' } : { kind: failure })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [inviteId])

  if (inviteId === undefined) {
    return (
      <Alert variant="destructive">
        <AlertDescription>Missing invite id.</AlertDescription>
      </Alert>
    )
  }

  if (state.kind === 'loading') {
    return null
  }
  if (state.kind === 'notFound') {
    return (
      <Alert variant="destructive">
        <AlertDescription>
          This invite doesn't exist, or it has expired and been removed.
        </AlertDescription>
      </Alert>
    )
  }
  if (state.kind === 'networkError') {
    return (
      <Alert variant="destructive">
        <AlertDescription>Couldn't reach the server. Try again.</AlertDescription>
      </Alert>
    )
  }
  if (state.kind === 'invalid') {
    return (
      <Alert variant="destructive">
        <AlertDescription>{verificationMessageFor(state.reason)}</AlertDescription>
      </Alert>
    )
  }

  if (accepted) {
    return (
      <div className="flex w-full max-w-sm flex-col gap-4">
        <h1 className="text-lg font-semibold">You're in</h1>
        <p className="text-sm text-muted-foreground">
          Your acceptance has been recorded. The group key will arrive automatically the next time
          the person who invited you logs in.
        </p>
      </div>
    )
  }

  const handleAccept = () => {
    if (session.userId === null) {
      return
    }
    if (state.macKey === undefined) {
      // No fragment (or a malformed one) -- see parseInviteFragment's own
      // doc comment. Refusing here, rather than silently accepting
      // without a MAC, is deliberate: an accept with no inviteMACKey would
      // leave step 3 with nothing to verify the response against, which is
      // exactly the gap deriveInviteMACKey's own doc comment describes.
      setAcceptError(
        "This invite link is missing part of its address (the part after '#'). Ask the person who invited you to resend the full link.",
      )
      return
    }
    const userId = session.userId
    const macKey = state.macKey
    setAcceptError(null)
    setAccepting(true)
    void (async () => {
      const result = await runAcceptInvite(
        { signInviteAcceptance, acceptInvite, userId },
        inviteId,
        macKey,
      )
      setAccepting(false)
      if (!result.ok) {
        setAcceptError(acceptErrorMessageFor(result.kind, result.error))
        return
      }
      setAccepted(true)
    })()
  }

  return (
    <div className="flex w-full max-w-sm flex-col gap-4">
      <h1 className="text-lg font-semibold">You've been invited</h1>
      {state.fingerprint !== '' && (
        <div className="flex flex-col gap-1">
          <p className="text-xs text-muted-foreground">Inviter's fingerprint (matched):</p>
          <p className="font-mono text-xs break-all">{state.fingerprint}</p>
        </div>
      )}
      {acceptError !== null && (
        <Alert variant="destructive">
          <AlertDescription>{acceptError}</AlertDescription>
        </Alert>
      )}
      {session.userId === null ? (
        <div className="flex flex-col gap-2">
          <p className="text-sm text-muted-foreground">
            Log in or create an account, then come back to this link to accept.
          </p>
          <div className="flex gap-2">
            <Button asChild variant="outline" className="flex-1">
              <Link to="/login">Log in</Link>
            </Button>
            <Button asChild className="flex-1">
              <Link to="/signup">Sign up</Link>
            </Button>
          </div>
        </div>
      ) : (
        <Button onClick={handleAccept} disabled={accepting}>
          {accepting ? 'Accepting…' : 'Accept invite'}
        </Button>
      )}
    </div>
  )
}
