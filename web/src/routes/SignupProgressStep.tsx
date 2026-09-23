// #33: "key generation with honest progress (Argon2id takes real time)."
// Honest, per the prior session's discussion in worker.ts: hash-wasm's
// argon2id has no internal progress callback, so this is a coarse 3-step
// signal tied to signup's three real independent Argon2id derivations
// (password/recovery/verifier keys), not a smoothly interpolated bar --
// the label and step number only change when that step's derivation has
// actually finished.

import { Progress } from '@/components/ui/progress'
import type { SignupProgressEvent } from '@/lib/crypto/worker-protocol'

export function SignupProgressStep({ progress }: { progress: SignupProgressEvent | null }) {
  const step = progress?.step ?? 0
  const totalSteps = progress?.totalSteps ?? 3
  const label = progress?.label ?? 'Generating your keys'

  return (
    <div className="flex w-full max-w-md flex-col items-center gap-4 text-center">
      <h1 className="text-xl font-semibold">Setting up your account</h1>
      <p className="text-sm text-muted-foreground">{label}…</p>
      <Progress value={(step / totalSteps) * 100} className="w-full" />
      <p className="text-xs text-muted-foreground">
        Step {Math.max(step, 1)} of {totalSteps}
      </p>
    </div>
  )
}
