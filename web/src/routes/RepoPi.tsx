// The floating π (#395): a small link to the source repository, fixed to the bottom right corner of
// the viewport so it stays put while the page scrolls. Rendered once, beside the routes in App.tsx;
// repoPiShown decides where it hides.

import { useLocation } from 'react-router'
import { useSession } from '@/lib/session/useSession'
import { REPO_LINK_REL, REPO_URL, repoPiShown } from './repoLink'

export function RepoPi() {
  const session = useSession()
  const { pathname } = useLocation()
  if (!repoPiShown(pathname, session)) return null
  return <RepoPiLink />
}

/** The link itself, with no hooks, so a test can render it on its own. */
export function RepoPiLink() {
  return (
    <a
      href={REPO_URL}
      target="_blank"
      rel={REPO_LINK_REL}
      aria-label="UndergroundBB source code on GitHub"
      title="Source code on GitHub"
      className="fixed right-[calc(0.75rem+env(safe-area-inset-right))] bottom-[calc(0.75rem+env(safe-area-inset-bottom))] z-50 inline-flex size-8 items-center justify-center rounded-full border border-border bg-background font-serif text-lg leading-none text-muted-foreground shadow-sm transition-colors outline-none hover:text-primary focus-visible:text-primary focus-visible:ring-[3px] focus-visible:ring-ring/50"
    >
      π
    </a>
  )
}
