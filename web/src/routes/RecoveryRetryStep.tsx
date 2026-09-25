// Shown when reset()'s response was lost after its write may have already
// committed (runRecovery.ts's 'resetResponseLost', issue #130). Offers the
// one thing a plain "go back and try again" cannot safely do: resend the
// EXACT same request (RecoveryScreen.tsx passes step.resume straight back
// into runRecovery), recognized server-side by its idempotency token
// whether or not the first attempt actually landed. onGiveUp is the escape
// hatch to #131's change-password screen for the (rare) case where a retry
// also fails ambiguously, or the user would rather not wait.

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

export function RecoveryRetryStep({
  message,
  onRetry,
  onGiveUp,
}: {
  message: string
  onRetry: () => void
  onGiveUp: () => void
}) {
  return (
    <div className="flex w-full max-w-sm flex-col gap-4">
      <div className="flex flex-col gap-1 text-center">
        <h1 className="text-xl font-semibold">Recovering your account</h1>
      </div>
      <Alert>
        <AlertDescription>{message}</AlertDescription>
      </Alert>
      <Button type="button" onClick={onRetry}>
        Try again
      </Button>
      <Button type="button" variant="outline" onClick={onGiveUp}>
        Start over
      </Button>
    </div>
  )
}
