import type { SessionState } from './session-context'

export type RedirectDecision = 'pending' | 'redirect' | 'allow'

/**
 * The pure decision RedirectIfAuthenticated's effect makes on every run:
 * given the current (possibly already-latched) decision and the current
 * session, what should the decision become? Factored out so the actual bug
 * this file exists to pin -- a decision must never change once it stops
 * being 'pending', however session.userId changes afterward -- is
 * unit-testable directly, the same convention resolveBootstrapUserID.ts
 * already established for SessionContext's own bootstrap logic (this
 * codebase's vitest runs in environment: 'node', with no jsdom/RTL, so
 * testable here means logic outside the component).
 *
 * See RedirectIfAuthenticated.tsx's own header comment for why latching
 * matters: an earlier version re-decided on every session change, which let
 * SignupScreen's mid-flow session.login() call redirect away and unmount
 * SignupScreen before it could show the recovery code.
 */
export function nextRedirectDecision(
  current: RedirectDecision,
  status: SessionState['status'],
  userId: SessionState['userId'],
): RedirectDecision {
  if (current !== 'pending' || status === 'loading') {
    return current
  }
  return userId !== null ? 'redirect' : 'allow'
}
