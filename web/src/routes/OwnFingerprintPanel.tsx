// A member's own key fingerprint, readable by any logged-in user (#178). An
// admin re-admitting someone compares the fingerprint of the keys the server
// serves for them against what that person reads out from here, so the only
// control against a server-invented account needs this to be reachable by a
// plain member. Prop-driven so it is tested with renderToStaticMarkup.

export type OwnFingerprintState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly fingerprint: string }
  | { readonly status: 'unavailable' }

export function OwnFingerprintPanel({ state }: { readonly state: OwnFingerprintState }) {
  return (
    <div className="flex w-full max-w-md flex-col gap-1">
      <p className="text-sm font-medium">Your key fingerprint</p>
      {state.status === 'loading' && <p className="text-xs text-muted-foreground">Loading…</p>}
      {state.status === 'ready' && (
        <p className="font-mono text-xs break-all">{state.fingerprint}</p>
      )}
      {state.status === 'unavailable' && (
        <p className="text-xs text-muted-foreground">Log in again to see your fingerprint.</p>
      )}
      <p className="text-xs text-muted-foreground">
        If an admin asks to re-admit you, read this out to them in person or on a call they know is
        you. Do not send it in a message.
      </p>
    </div>
  )
}
