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
 * `loggingIn` renders a 4th, final step after the worker's 3 signupProgress
 * events: register() only creates the account, it does not establish a
 * session (only POST /api/auth/verify sets the cookie -- see SignupScreen's
 * own comment), so signup runs a real login immediately afterward. That
 * derivation is honest progress too -- it takes as long as any of the other
 * three -- so it gets its own step rather than a blank screen.
 */
export function SignupProgressStep({
  progress,
  loggingIn = false,
}: {
  progress: SignupProgressEvent | null
  loggingIn?: boolean
}) {
  const totalSteps = 4
  const step = loggingIn ? 4 : (progress?.step ?? 0)
  const label = loggingIn ? 'Logging you in…' : (progress?.label ?? 'Generating your keys…')

  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4 text-center">
      <h1 className="text-xl font-semibold">Setting up your account</h1>
      <p className="text-sm text-muted-foreground">{label}</p>
      <Progress value={(step / totalSteps) * 100} className="w-full" />
      <p className="text-xs text-muted-foreground">
        Step {Math.max(step, 1)} of {totalSteps}
      </p>
    </div>
  )
}
