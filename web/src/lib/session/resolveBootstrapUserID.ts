import type { SessionResponse } from '@/lib/api/auth'

/**
 * Turns a GET /api/auth/session outcome into the userId SessionProvider
 * should adopt at bootstrap (issue #32). Factored out of SessionContext.tsx
 * so this decision -- what to do with each shape getSession can produce,
 * including its failure mode -- is unit-testable without mounting a
 * component or React at all, matching this codebase's convention elsewhere
 * (runSignup.ts, runRecovery.ts) of keeping the actual logic outside the
 * component.
 *
 * A rejected getSession() (network error, 5xx) resolves to null here, the
 * same as an explicit authenticated: false -- see SessionContext.tsx's own
 * comment on why that's the only defensible default.
 */
export async function resolveBootstrapUserID(
  getSession: () => Promise<SessionResponse>,
): Promise<string | null> {
  try {
    const session = await getSession()
    return session.authenticated ? (session.userId ?? null) : null
  } catch {
    return null
  }
}
