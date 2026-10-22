// #62: the logged-in "Rotate keys" screen. The flow itself is runKeyRotation.ts;
// this component loads what the review step shows, runs the flow, and shows the
// new recovery code, which the user must store before leaving.
//
// States: loading -> review -> running -> recoveryCode, or a failure that
// returns to review (an attempt that may still commit stays resumable, so
// "Rotate my keys" again resends the same signed request).

import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { ApiError, getAccountCredentials } from '@/lib/api/auth'
import { getGroup, getKeychain, listGroups } from '@/lib/api/groups'
import { sentInvites, revokeInvite } from '@/lib/api/invites'
import { putHandoff, rotateKeys } from '@/lib/api/keyRotation'
import { listAllPins } from '@/lib/api/pins'
import { getUser } from '@/lib/api/users'
import { listAllVerifications } from '@/lib/api/verifications'
import {
  beginKeyRotation,
  commitKeyRotation,
  decryptGroupNames,
  discardKeyRotation,
  hasLiveKeys,
  signKeyRotation,
  wrapHandoff,
} from '@/lib/crypto/worker-client'
import type { SignupProgressEvent } from '@/lib/crypto/worker-protocol'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import { useSession } from '@/lib/session/useSession'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { groupLabel } from './groupLabel'
import { RecoveryCodeStep } from './RecoveryCodeStep'
import { failureMessage, stepText } from './rotateKeysCopy'
import { RotateKeysReview } from './RotateKeysReview'
import { runListGroups } from './runListGroups'
import {
  preflightKeyRotation,
  runKeyRotation,
  type KeyRotationAttempt,
  type KeyRotationDeps,
  type KeyRotationPreflight,
  type KeyRotationStep,
} from './runKeyRotation'

const LOAD_ERROR = "Couldn't load your groups. Check your connection and try again."

type Step =
  | { readonly name: 'loading' }
  | { readonly name: 'loadFailed' }
  | { readonly name: 'review'; readonly pre: KeyRotationPreflight }
  | {
      readonly name: 'running'
      readonly pre: KeyRotationPreflight
      readonly step: KeyRotationStep
      readonly progress: SignupProgressEvent | null
    }
  | { readonly name: 'recoveryCode'; readonly recoveryCode: string }

const deps: KeyRotationDeps = {
  hasLiveKeys,
  getCredentials: getAccountCredentials,
  getUser,
  listGroups,
  getGroup,
  sentInvites,
  revokeInvite,
  listAllPins,
  listAllVerifications,
  beginKeyRotation,
  wrapHandoff,
  putHandoff,
  signKeyRotation,
  rotateKeys,
  commitKeyRotation,
  discardKeyRotation,
}

export function RotateKeysScreen() {
  const [step, setStep] = useState<Step>({ name: 'loading' })
  const [labels, setLabels] = useState<ReadonlyMap<string, string>>(new Map())
  const [error, setError] = useState<string | null>(null)
  const [needsLogin, setNeedsLogin] = useState(false)
  const navigate = useNavigate()
  const session = useSession()
  // The signed request of an attempt that did not commit, kept so a retry
  // resends it rather than minting a second set of keys.
  const attempt = useRef<KeyRotationAttempt>({})
  const busy = step.name === 'running'

  useEffect(() => {
    if (step.name !== 'loading') {
      return
    }
    let cancelled = false
    void (async () => {
      try {
        const pre = await preflightKeyRotation(deps)
        const groups = await runListGroups({
          listGroups,
          decryptGroupNames,
          getNameChain: (gid, nameGen, gen) => fetchNameChain(getKeychain, gid, nameGen, gen),
          getCachedGroupName,
          setCachedGroupName,
          userId: pre.userId,
        })
        if (!cancelled) {
          setLabels(new Map(groups.map((g) => [g.groupId, groupLabel(g)])))
          setStep({ name: 'review', pre })
        }
      } catch (err) {
        if (cancelled) {
          return
        }
        if (err instanceof ApiError && err.status === 401) {
          session.logout()
          navigate('/login', { replace: true })
          return
        }
        setError(LOAD_ERROR)
        setStep({ name: 'loadFailed' })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [step.name, navigate, session])

  // A rotation in flight, or a recovery code not yet written down, is lost on
  // reload (the new keys live only in the worker).
  useEffect(() => {
    if (step.name !== 'running' && step.name !== 'recoveryCode') {
      return
    }
    const handleBeforeUnload = (e: BeforeUnloadEvent): void => {
      e.preventDefault()
    }
    window.addEventListener('beforeunload', handleBeforeUnload)
    return () => {
      window.removeEventListener('beforeunload', handleBeforeUnload)
    }
  }, [step.name])

  const labelFor = (groupId: string): string => labels.get(groupId) ?? '(a group)'

  const reviewGroups = useMemo(
    () =>
      step.name === 'review'
        ? step.pre.adminGroups.map((g) => ({
            groupId: g.groupId,
            label: labels.get(g.groupId) ?? '(a group)',
            open: g.open,
          }))
        : [],
    [step, labels],
  )

  const handleSubmit = (pre: KeyRotationPreflight, newPassword: string) => {
    setError(null)
    setStep({ name: 'running', pre, step: { name: 'preparing' }, progress: null })
    void (async () => {
      const result = await runKeyRotation(deps, pre, newPassword, attempt.current, {
        onStep: (s) => {
          setStep((cur) => (cur.name === 'running' ? { ...cur, step: s, progress: null } : cur))
        },
        onProgress: (p) => {
          setStep((cur) => (cur.name === 'running' ? { ...cur, progress: p } : cur))
        },
      })
      if (result.ok) {
        attempt.current = {}
        setStep({ name: 'recoveryCode', recoveryCode: result.recoveryCode })
        return
      }
      const { failure } = result
      if (failure.kind !== 'unreachable') {
        // Nothing committed and nothing will: drop the new keys and let pins
        // and verifications be signed again.
        attempt.current = {}
        await discardKeyRotation().catch(() => undefined)
      }
      if (failure.kind === 'needsLogin' || failure.kind === 'authRequired') {
        setNeedsLogin(true)
      }
      setError(failureMessage(failure, labelFor))
      setStep({ name: 'review', pre })
    })()
  }

  switch (step.name) {
    case 'loading':
      return <p className="text-sm text-muted-foreground">Loading your groups…</p>
    case 'loadFailed':
      return (
        <div className="flex w-full max-w-sm flex-col gap-4">
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <Button
            onClick={() => {
              setError(null)
              setStep({ name: 'loading' })
            }}
          >
            Try again
          </Button>
        </div>
      )
    case 'review':
      return (
        <div className="flex w-full max-w-lg flex-col gap-4">
          {needsLogin && (
            <Button
              variant="outline"
              onClick={() => {
                session.logout()
                navigate('/login', { replace: true })
              }}
            >
              Log in again
            </Button>
          )}
          <RotateKeysReview
            groups={reviewGroups}
            invitesToRevoke={step.pre.invitesToRevoke.length}
            invitesAwaitingCompletion={step.pre.invitesAwaitingCompletion}
            error={error}
            onSubmit={(pw) => {
              handleSubmit(step.pre, pw)
            }}
          />
        </div>
      )
    case 'running': {
      const p = step.progress
      return (
        <div className="flex w-full max-w-sm flex-col gap-3" aria-busy={busy}>
          <h1 className="text-xl font-semibold">Rotating your keys</h1>
          <p className="text-sm">{stepText(step.step)}</p>
          {p !== null && (
            <>
              <Progress value={(p.step / p.totalSteps) * 100} />
              <p className="text-xs text-muted-foreground">{p.label}</p>
            </>
          )}
          <p className="text-xs text-muted-foreground">
            Keep this tab open until you see your new recovery code.
          </p>
        </div>
      )
    }
    case 'recoveryCode':
      return (
        <RecoveryCodeStep
          recoveryCode={step.recoveryCode}
          onAcknowledged={() => {
            navigate('/', { replace: true })
          }}
        />
      )
  }
}
