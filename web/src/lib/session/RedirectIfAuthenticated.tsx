// Issue #32's other direction from RequireAuth: keeps an already-logged-in
// visitor from landing back on /login or /signup, e.g. a bookmark or a
// back-navigation after logging in elsewhere in the same tab. Same
// loading-wait rationale as RequireAuth -- see SessionContext's own comment.
//
// Decides exactly once -- the first time session.status becomes 'ready' --
// and never re-decides after that, even as session.userId keeps changing on
// later renders. Reviewer-caught regression on #32's own PR: an earlier
// version re-decided on every session change, which meant SignupScreen's own
// session.login(userId) call (fired mid-flow, before the recovery code and
// theme steps render -- see SignupScreen.tsx's onLogin) made this component
// redirect to / immediately, unmounting SignupScreen and losing the one and
// only copy of the recovery code -- precisely what #124/#134 exist to
// prevent. Latching the decision once matches this guard's actual purpose
// too: it exists to catch a visitor who *arrives* already logged in, not one
// who logs in *while on the page* -- SignupScreen and LoginScreen already
// navigate themselves once their own flow finishes, so re-deciding mid-flow
// was never doing useful work, only harm.
import { useEffect, useState, type ReactNode } from 'react'
import { Navigate } from 'react-router'
import { nextRedirectDecision } from './nextRedirectDecision'
import { useSession } from './useSession'

export function RedirectIfAuthenticated({ children }: { children: ReactNode }) {
  const session = useSession()
  const [decision, setDecision] = useState<ReturnType<typeof nextRedirectDecision>>('pending')

  useEffect(() => {
    // nextRedirectDecision's own `current !== 'pending'` check is what makes
    // the decision stick: once set, this effect still re-runs on every later
    // session change (status/userId are both in the deps array, honestly,
    // per exhaustive-deps), but returns `current` unchanged every time after
    // that -- there is nothing left to decide.
    const next = nextRedirectDecision(decision, session.status, session.userId)
    if (next === decision) {
      return
    }
    // oxlint's set-state-in-effect warning assumes setState-in-effect is
    // mirroring an already-derivable value, which is the case it's usually
    // right to flag. Here it isn't: session.status resolves asynchronously,
    // after this component has already mounted and rendered 'pending' at
    // least once, so there is no synchronous render this decision could be
    // computed in instead -- that's what makes this a legitimate "wait for
    // an external, one-time answer" effect rather than the redundant
    // derived-state effect the rule exists to catch.
    // oxlint-disable-next-line react-hooks/set-state-in-effect
    setDecision(next)
  }, [decision, session.status, session.userId])

  switch (decision) {
    case 'pending':
      return null
    case 'redirect':
      return <Navigate to="/" replace />
    case 'allow':
      return children
  }
}
