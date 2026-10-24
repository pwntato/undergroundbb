// #62: the logged-in "Rotate keys" screen. The flow itself is runKeyRotation.ts;
// this component loads what the review step shows, runs the flow, and shows the
// new recovery code, which the user must store before leaving.
//
// States: loading -> review -> running -> recoveryCode, or a failure that
// returns to review (an attempt that may still commit stays resumable, so
// "Rotate my keys" again resends the same signed request).

import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { ApiError, challenge, getAccountCredentials } from '@/lib/api/auth'
import { getGroup, getKeychain, listGroups } from '@/lib/api/groups'
import { sentInvites, revokeInvite } from '@/lib/api/invites'
import { listHandoffs, putHandoff, rotateKeys } from '@/lib/api/keyRotation'
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
import { failureMessage, selfRekeyText, stepText } from './rotateKeysCopy'
import { RotateKeysRetry } from './RotateKeysRetry'
import { RotateKeysReview } from './RotateKeysReview'
import { runListGroups } from './runListGroups'
import { makeSelfRekeyDeps } from './rotationDeps'
import { runSelfRekey } from './runSelfRekey'
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
  | { readonly name: 'rekeying' }
  | { readonly name: 'rekeyDone'; readonly lines: readonly string[] }
  | {
      readonly name: 'retry'
      readonly pre: KeyRotationPreflight
      readonly recoveryCode: string
    }
  | {
      readonly name: 'recoveryCode'
      readonly recoveryCode: string
      /** No session for the new keys: acknowledging goes to log in, not Home. */
      readonly needsRelogin: boolean
    }

const deps: KeyRotationDeps = {
  hasLiveKeys,
  getCredentials: getAccountCredentials,
  getUser,
  challenge,
  listGroups,
  getGroup,
  sentInvites,
  revokeInvite,
  listAllPins,
  listAllVerifications,
  beginKeyRotation,
  wrapHandoff,
  putHandoff,
  listHandoffs,
  signKeyRotation,
  rotateKeys,
  wait: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
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

  // The new keys are pending in the worker from beginKeyRotation until the
  // rotation commits or is discarded, and while they are, signPin and
  // signVerification refuse. A failure that leaves the attempt resumable but
  // not sent ('unreachable') keeps them for the retry; leaving the screen ends
  // that retry, so drop them. Not while a run is in flight (it carries on
  // without this screen), and never once the send's outcome is unknown: those
  // keys and the recovery code may be the only copy.
  const mounted = useRef(true)
  const stepName = useRef(step.name)
  useEffect(() => {
    stepName.current = step.name
  }, [step.name])
  useEffect(() => {
    const held = attempt
    mounted.current = true
    return () => {
      mounted.current = false
      if (stepName.current === 'review' && held.current.begun !== undefined) {
        if (held.current.ambiguous !== true) {
          held.current = {}
          void discardKeyRotation().catch(() => undefined)
        }
      }
    }
  }, [])

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
    if (
      step.name !== 'running' &&
      step.name !== 'recoveryCode' &&
      step.name !== 'retry' &&
      step.name !== 'rekeying'
    ) {
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

  // Finishes the key changes a rotation left waiting (#62): the self re-key of
  // each group from its handoff row. It carries on if the screen is left (it
  // resumes from server state), so the outcome is shown only when still here.
  const finishRekeys = (pre: KeyRotationPreflight) => {
    setError(null)
    setStep({ name: 'rekeying' })
    void (async () => {
      const lines: string[] = []
      try {
        const rows = await listHandoffs()
        const rekeyDeps = makeSelfRekeyDeps(pre.userId)
        for (const groupId of pre.pendingSelfRekeys) {
          const row = rows.find((r) => r.groupId === groupId)
          if (row === undefined) {
            lines.push(`${labelFor(groupId)}: nothing left to finish.`)
            continue
          }
          const outcome = await runSelfRekey(rekeyDeps, row)
          lines.push(selfRekeyText(outcome, labelFor(groupId), () => 'a member'))
        }
      } catch (err) {
        lines.push(`Stopped: ${err instanceof Error ? err.message : String(err)} Try again.`)
      }
      if (mounted.current) setStep({ name: 'rekeyDone', lines })
    })()
  }

  // Runs the flow. A retry passes no password: the request it resends was
  // signed under the one chosen the first time.
  const start = (pre: KeyRotationPreflight, newPassword: string) => {
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
        setStep({
          name: 'recoveryCode',
          recoveryCode: result.recoveryCode,
          needsRelogin: result.needsRelogin,
        })
        return
      }
      const { failure } = result
      if (failure.kind === 'unconfirmed') {
        // Sent, outcome unknown: keep the attempt and the pending keys, and show
        // the recovery code. Nothing here may be discarded.
        setError(failureMessage(failure, labelFor))
        setStep({ name: 'retry', pre, recoveryCode: failure.recoveryCode })
        return
      }
      if (failure.kind === 'unreachable' && !mounted.current) {
        // The screen was left mid-run: no retry will be made, so the pending
        // keys must not outlive it (signPin/signVerification refuse while set).
        attempt.current = {}
        await discardKeyRotation().catch(() => undefined)
        return
      }
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
          {step.pre.pendingSelfRekeys.length > 0 ? (
            <>
              <Alert>
                <AlertDescription>
                  {failureMessage(
                    { kind: 'handoffPending', groups: step.pre.pendingSelfRekeys },
                    labelFor,
                  )}
                </AlertDescription>
              </Alert>
              <Button
                onClick={() => {
                  finishRekeys(step.pre)
                }}
              >
                Finish key changes
              </Button>
            </>
          ) : (
            <RotateKeysReview
              groups={reviewGroups}
              invitesToRevoke={step.pre.invitesToRevoke.length}
              invitesAwaitingCompletion={step.pre.invitesAwaitingCompletion}
              error={error}
              onSubmit={(pw) => {
                start(step.pre, pw)
              }}
            />
          )}
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
    case 'rekeying':
      return (
        <div className="flex w-full max-w-sm flex-col gap-3" aria-busy>
          <h1 className="text-xl font-semibold">Finishing your key changes</h1>
          <p className="text-sm">Re-keying your groups…</p>
          <p className="text-xs text-muted-foreground">
            Keep this tab open until this finishes. If you leave, it picks up where it stopped.
          </p>
        </div>
      )
    case 'rekeyDone':
      return (
        <div className="flex w-full max-w-lg flex-col gap-4">
          <h1 className="text-xl font-semibold">Key changes</h1>
          <ul className="list-disc space-y-1 pl-5 text-sm">
            {step.lines.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
          <Button
            onClick={() => {
              setStep({ name: 'loading' })
            }}
          >
            Continue
          </Button>
        </div>
      )
    case 'retry':
      return (
        <RotateKeysRetry
          message={error ?? ''}
          recoveryCode={step.recoveryCode}
          onRetry={() => {
            start(step.pre, '')
          }}
        />
      )
    case 'recoveryCode':
      return (
        <div className="flex w-full max-w-lg flex-col items-center gap-4">
          {step.needsRelogin && (
            <Alert>
              <AlertDescription>
                Your keys were rotated. After you save the code below, log in again with your new
                password.
              </AlertDescription>
            </Alert>
          )}
          <RecoveryCodeStep
            recoveryCode={step.recoveryCode}
            onAcknowledged={() => {
              if (step.needsRelogin) {
                session.logout()
                navigate('/login', { replace: true })
                return
              }
              navigate('/', { replace: true })
            }}
          />
        </div>
      )
  }
}
