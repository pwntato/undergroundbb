// #33: "key generation with honest progress (Argon2id takes real time)."
// Honest, per the prior session's discussion in worker.ts: hash-wasm's
// argon2id has no internal progress callback, so this is a coarse 3-step
// signal tied to signup's three real independent Argon2id derivations
// (password/recovery/verifier keys), not a smoothly interpolated bar.
//
// worker.ts posts each event AFTER that step's derivation finishes, so the
// label is phrased as a completion ("Password key ready"), not an
// in-progress verb -- an in-progress phrasing would be wrong for the whole
// duration of whichever step is actually still running, since nothing
// reports that a step has started, only that the previous one is done.

import { Progress } from '@/components/ui/progress'
import type { SignupProgressEvent } from '@/lib/crypto/worker-protocol'

/**
 * `leadingStep`/`trailingStep` each add one step around the worker's own
 * signupProgress events, for a network call the worker can't report
 * progress on itself but which is real, honest work the user is waiting on
 * -- it deserves its own step rather than a blank screen or a premature
 * 100%. SignupScreen uses `trailingStep` for the post-register login
 * (register() only creates the account; only POST /api/auth/verify sets
 * the session cookie). RecoveryScreen (#128) uses both: `leadingStep` for
 * POST /api/account/recovery-code/release (the code check happens before
 * the worker can even start), and `trailingStep` for
 * PUT /api/account/recovery-code (reset() -- the write that actually
 * invalidates the redeemed code; completeRecovery's worker steps only
 * compute the new material, they don't submit it).
 *
 * Every caller must pass the same `leadingStep`/`trailingStep` props on
 * every phase of its flow (only `currentStep` varies) -- PR #129 review
 * caught that a caller only passing `trailingStep` on its final phase made
 * `totalSteps` change mid-flow (a premature 100% on the phase before, then
 * a bigger denominator appearing on the next one). `heading` lets each
 * caller supply its own top-level copy without forking this component.
 *
 * `totalSteps` comes from `progress.totalSteps` -- the worker's own call
 * knows its real step count (3 for generateSignupMaterial, 4 for
 * completeRecovery's extra upfront unwrap) -- plus one for each of
 * `leadingStep`/`trailingStep` present. Before the first `progress` event
 * arrives, `progress` is null and there is no authoritative count yet;
 * `initialTotalSteps` (the worker call's step count once it starts) fills
 * that gap so the denominator doesn't visibly change once the first event
 * does land.
 *
 * `currentStep` names which numbered step is active while a leading or
 * trailing network call is in flight (1 for leading, `totalSteps` for
 * trailing); it's meaningless -- and ignored -- while a `progress` event is
 * what's driving the display, since that carries its own step number
 * already.
 *
 * Between `currentStep` no longer being `'leading'`/`'trailing'` and the
 * worker's first `progress` event landing, the display must hold at
 * `workerStepOffset` (not drop to 0) and show `pendingLabel` -- PR #129
 * round 2 caught that recovery's bar and label briefly reverted to
 * signup's own ("Generating your keys…") right after `releasing` handed
 * off to `recovering`, even though the leading step had already put the
 * bar at position 1 and real work (the upfront unwrap) was already
 * running. Signup has no leading step, so `workerStepOffset` is 0 there
 * and this only matters for callers like RecoveryScreen that have one.
 */
export function SignupProgressStep({
  progress,
  initialTotalSteps = 3,
  leadingStep,
  trailingStep,
  currentStep,
  heading = 'Setting up your account',
  pendingLabel = 'Generating your keys…',
}: {
  progress: SignupProgressEvent | null
  initialTotalSteps?: number
  leadingStep?: string
  trailingStep?: string
  currentStep?: 'leading' | 'trailing'
  heading?: string
  /**
   * Shown (alongside the leading step's own position on the bar, if any)
   * while the worker's own call is running but hasn't posted its first
   * event yet -- e.g. recovery's upfront unwrap, a real Argon2id derivation
   * with no step of its own. Defaults to signup's copy, since signup has no
   * leading step and this label is only reachable there for an instant.
   */
  pendingLabel?: string
}) {
  const extraSteps = (leadingStep === undefined ? 0 : 1) + (trailingStep === undefined ? 0 : 1)
  const workerTotalSteps = progress?.totalSteps ?? initialTotalSteps
  const totalSteps = workerTotalSteps + extraSteps
  const workerStepOffset = leadingStep === undefined ? 0 : 1

  let step: number
  let label: string
  if (currentStep === 'leading' && leadingStep !== undefined) {
    step = 1
    label = leadingStep
  } else if (currentStep === 'trailing' && trailingStep !== undefined) {
    step = totalSteps
    label = trailingStep
  } else {
    // Before the worker's first event, step must still reflect
    // workerStepOffset -- a leading step (recovery) has already claimed
    // position 1, so the bar must hold there, not drop to 0, while the
    // worker's own first derivation (uncounted work with no event of its
    // own) is in flight. PR #129 round 2 caught that recovery's bar and
    // label briefly reverted to signup's between releasing -> recovering.
    step = (progress?.step ?? 0) + workerStepOffset
    label = progress?.label ?? pendingLabel
  }

  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4 text-center">
      <h1 className="text-xl font-semibold">{heading}</h1>
      <p className="text-sm text-muted-foreground">{label}</p>
      <Progress value={(step / totalSteps) * 100} className="w-full" />
      <p className="text-xs text-muted-foreground">
        Step {Math.max(step, 1)} of {totalSteps}
      </p>
    </div>
  )
}
