// A member's own key fingerprint, readable by any logged-in user (#178). An
// admin re-admitting someone compares the fingerprint of the keys the server
// serves for them against what that person reads out from here, so the only
// control against a server-invented account needs this to be reachable by a
// plain member. Prop-driven so it is tested with renderToStaticMarkup.

import { Button } from '@/components/ui/button'
import { FingerprintBlock } from './FingerprintBlock'

export type OwnFingerprintState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly fingerprint: string }
  | { readonly status: 'unavailable' }

export function OwnFingerprintPanel({
  state,
  onReauthenticate,
}: {
  readonly state: OwnFingerprintState
  /** Opens the in-place password step; the fingerprint needs this tab's keys. */
  readonly onReauthenticate: () => void
}) {
  return (
    <div className="flex w-full max-w-md flex-col gap-1">
      <p className="text-sm font-medium">Your key fingerprint</p>
      {state.status === 'loading' && <p className="text-xs text-muted-foreground">Loading…</p>}
      {state.status === 'ready' && <FingerprintBlock value={state.fingerprint} />}
      {state.status === 'unavailable' && (
        <div className="flex flex-col items-start gap-1">
          <p className="text-xs text-muted-foreground">
            This tab needs your password to show your fingerprint.
          </p>
          <Button type="button" variant="outline" size="sm" onClick={onReauthenticate}>
            Enter your password
          </Button>
        </div>
      )}
      <p className="text-xs text-muted-foreground">
        If an admin asks to re-admit you, or a member wants to check you, read this out to them in
        person or on a call they know is you. Do not send it in a message.
      </p>
    </div>
  )
}
