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

export interface LogoutClickDeps extends LogoutDeps {
  setLoggingOut: (loggingOut: boolean) => void
  setLogoutError: (message: string | null) => void
  navigate: (to: string, options: { replace: boolean }) => void
}

/**
 * What Home's "Log out" button does, in order: clear the last error, mark the button busy for the
 * length of the request, then either go to the signed-out home (replacing this entry, so Back does
 * not return to a signed-in screen) or show why it failed and stay signed in.
 */
export async function onLogoutClick(deps: LogoutClickDeps): Promise<void> {
  deps.setLogoutError(null)
  deps.setLoggingOut(true)
  const outcome = await runLogout(deps)
  deps.setLoggingOut(false)
  if (outcome.ok) {
    deps.navigate('/', { replace: true })
  } else {
    deps.setLogoutError(outcome.message)
  }
}
