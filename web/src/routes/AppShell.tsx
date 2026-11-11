// The signed-in app shell (#47): a group sidebar beside the page, a menu on a phone. It wraps every
// route; for a signed-out visitor, and on the screens that hold a one-time recovery code (the same
// list the Notifications header hides on, appHeaderPaths.ts: a link out would lose the code), it
// renders the page alone.
//
// It loads the group list once (useGroupsLoad) and shares it through GroupsContext, so the sidebar
// and Home agree. A private group's name needs this tab's keys; when they are cold the shell can
// show the password step in place of the page (requestReauth) and then reload the list.

import { useState, type ReactNode } from 'react'
import { useLocation, useNavigate } from 'react-router'
import { logoutRequest } from '@/lib/api/auth'
import { useSession } from '@/lib/session/useSession'
import { headerShownOn } from './appHeaderPaths'
import { GroupsContext } from './groupsContext'
import { ReauthenticateStep } from './ReauthenticateStep'
import { onLogoutClick } from './runLogout'
import { ShellFrame, ShellSidebar } from './ShellSidebar'
import { useGroupsLoad } from './useGroupsLoad'
import { useUsernames } from './useUsernames'

function SignedInShell({
  userId,
  children,
}: {
  readonly userId: string
  readonly children: ReactNode
}) {
  const session = useSession()
  const { pathname } = useLocation()
  const navigate = useNavigate()
  const { load, reload } = useGroupsLoad(userId)
  // The phone menu is open for the page it was opened on; going elsewhere closes it, derived here
  // rather than reset in an effect.
  const [openOn, setOpenOn] = useState<string | null>(null)
  const open = openOn === pathname
  const [reauthenticating, setReauthenticating] = useState(false)
  const [loggingOut, setLoggingOut] = useState(false)
  const [logoutError, setLogoutError] = useState<string | null>(null)
  const usernames = useUsernames(
    load.status === 'ready'
      ? load.groups.flatMap((g) => (g.dmWith === undefined ? [] : [g.dmWith]))
      : [],
  )

  const requestReauth = () => setReauthenticating(true)
  const onLogout = () =>
    onLogoutClick({
      logoutRequest,
      clearLocalSession: session.logout,
      setLoggingOut,
      setLogoutError,
      navigate,
    })

  return (
    <GroupsContext.Provider value={{ load, usernames, requestReauth }}>
      <ShellFrame
        open={open}
        onToggle={() => setOpenOn(open ? null : pathname)}
        sidebar={
          <ShellSidebar
            load={load}
            usernames={usernames}
            requestReauth={requestReauth}
            pathname={pathname}
            loggingOut={loggingOut}
            logoutError={logoutError}
            onLogout={onLogout}
          />
        }
      >
        {reauthenticating ? (
          <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-8">
            <ReauthenticateStep
              sessionUserId={userId}
              action="show private group names"
              onDone={() => {
                setReauthenticating(false)
                reload()
              }}
              onCancel={() => setReauthenticating(false)}
            />
          </main>
        ) : (
          children
        )}
      </ShellFrame>
    </GroupsContext.Provider>
  )
}

export function AppShell({ children }: { readonly children: ReactNode }) {
  const session = useSession()
  const { pathname } = useLocation()
  const userId = session.status === 'loading' ? null : session.userId
  if (userId === null || !headerShownOn(pathname)) {
    return <>{children}</>
  }
  // keyed: a different user starts with an empty list, not the last user's.
  return (
    <SignedInShell key={userId} userId={userId}>
      {children}
    </SignedInShell>
  )
}
