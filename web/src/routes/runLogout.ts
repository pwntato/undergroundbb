// Issue #222: user-initiated logout. The server call goes first and local
// state is only dropped once it succeeds -- clearing the keys while the
// cookie survives would look logged out here yet still be logged in on the
// next reload.

export interface LogoutDeps {
  logoutRequest: () => Promise<void>
  /** SessionContext.logout: drops worker keys, caches, and userId. */
  clearLocalSession: () => void
}

export type LogoutOutcome = { ok: true } | { ok: false; message: string }

export async function runLogout(deps: LogoutDeps): Promise<LogoutOutcome> {
  try {
    await deps.logoutRequest()
  } catch {
    return { ok: false, message: 'Could not log out. Check your connection and try again.' }
  }
  deps.clearLocalSession()
  return { ok: true }
}
