// #62: shown when rotate-keys was sent and its outcome is unknown. The request
// is already signed under the password the user chose, so there is no form to
// fill in again: a retry resends it (after checking whether it already landed).
// The recovery code is shown because it is the only copy if the rotation did
// land, and it costs nothing if it did not.

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'

export function RotateKeysRetry({
  message,
  recoveryCode,
  onRetry,
}: {
  message: string
  recoveryCode: string
  onRetry: () => void
}) {
  return (
    <div className="flex w-full max-w-sm flex-col gap-4">
      <h1 className="text-xl font-semibold">Rotation not confirmed</h1>
      <Alert variant="destructive">
        <AlertDescription>{message}</AlertDescription>
      </Alert>
      <div className="flex flex-col gap-1">
        <p className="text-sm font-medium">Your new recovery code</p>
        <code className="rounded border p-3 text-center font-mono text-base break-all select-all">
          {recoveryCode}
        </code>
      </div>
      <Button onClick={onRetry}>Try again</Button>
    </div>
  )
}
