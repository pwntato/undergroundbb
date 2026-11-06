// Where the app header (the Notifications link) is NOT shown (#69). Some screens hold a step that
// shows a recovery code exactly once, guarded by beforeunload because leaving loses it for good; a
// client-side link does not fire beforeunload, so a link out of those screens would lose the code
// with no prompt. Each of these screens has its own way out, so the whole route hides the header:
// signup and recovery show a new code, change password shows the replacement code, and rotate keys
// has steps that must not be abandoned mid-way.
//
// It asks the router's own matcher, not a string compare, so it agrees with which screen the router
// renders: paths match without regard to case and after decoding (/Signup, /%73ignup).

import { matchRoutes } from 'react-router'

const HIDDEN_ON = ['/signup', '/recovery', '/account/password', '/account/rotate-keys'].map(
  (path) => ({ path: `${path}/*` }),
)

/** Whether the header link is shown on this pathname. A trailing slash or a sub-path is the same route. */
export function headerShownOn(pathname: string): boolean {
  return matchRoutes(HIDDEN_ON, pathname) === null
}
