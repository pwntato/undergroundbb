// The public source repository (#395). The signed-out landing page links to it in words; every other
// page shows a small floating π in the bottom right corner (RepoPi.tsx) that links to it instead.
//
// The link opens a new tab, so it never navigates away from a screen holding a one-time recovery
// code (appHeaderPaths.ts), and the π can show there too. The site's Referrer-Policy is no-referrer,
// and the link also carries rel="noreferrer", so GitHub never sees which page it was clicked from.

import { matchRoutes } from 'react-router'

export const REPO_URL = 'https://github.com/pwntato/undergroundbb'

export const REPO_LINK_REL = 'noopener noreferrer'

/**
 * Whether the floating π shows. It hides only where Home shows the signed-out landing page, which
 * has the worded link: path / while signed out, and path / while the session is still loading
 * (Home renders nothing then, and the π would flash before the landing page). A signed-in member
 * sees their group home on /, and the π shows there.
 */
export function repoPiShown(
  pathname: string,
  session: { readonly status: 'loading' | 'ready'; readonly userId: string | null },
): boolean {
  const onLanding = matchRoutes([{ path: '/' }], pathname) !== null
  if (!onLanding) return true
  return session.status === 'ready' && session.userId !== null
}
