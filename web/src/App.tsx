import { BrowserRouter, Route, Routes } from 'react-router'
import { AcceptInviteScreen } from '@/routes/AcceptInviteScreen'
import { ChangePasswordScreen } from '@/routes/ChangePasswordScreen'
import { CreateGroupScreen } from '@/routes/CreateGroupScreen'
import { CreateInviteScreen } from '@/routes/CreateInviteScreen'
import { GroupMembersScreen } from '@/routes/GroupMembersScreen'
import { GroupSettingsScreen } from '@/routes/GroupSettingsScreen'
import { Home } from '@/routes/Home'
import { InvitesScreen } from '@/routes/InvitesScreen'
import { LoginScreen } from '@/routes/LoginScreen'
import { RecoveryScreen } from '@/routes/RecoveryScreen'
import { SignupScreen } from '@/routes/SignupScreen'
import { RedirectIfAuthenticated } from '@/lib/session/RedirectIfAuthenticated'
import { RequireAuth } from '@/lib/session/RequireAuth'
import { SessionProvider } from '@/lib/session/SessionContext'

/**
 * Application shell: session state + routing. #33 adds the first real
 * screens (signup, login) on top of the placeholder scaffold; #128 adds
 * recovery; #131 adds the logged-in change-password/new-recovery-code
 * screen; #32 adds the session bootstrap and the guards below; #34 adds
 * group creation; #36 adds the group detail/settings screen; #37 adds the member list and role management screen; #38/#39 add the invite handshake's two screens (#40's
 * own step 3 has no screen at all -- it runs automatically on login, see
 * LoginScreen's own runCompleteInvites call); everything else this
 * milestone needs (the board views, etc.) arrives with the features that
 * need them.
 *
 * /groups/new and /groups/:groupId/invite both use RequireAuth like
 * /account/password -- CreateGroupScreen/CreateInviteScreen additionally
 * need the crypto worker's cached signing/wrapping keys to be live
 * (populated by a prior completeLogin in this worker instance's lifetime),
 * which RequireAuth's session check cannot see; each screen's own error
 * handling covers a cold cache separately, the same split
 * ChangePasswordScreen's header comment describes between RequireAuth and
 * its own live bootstrap check.
 *
 * /invites/:inviteId is deliberately UNGUARDED, like /recovery -- an
 * invite is a link handed to someone who may not have an account yet
 * (models.Invite's own doc comment, Go side), so GET /api/invites/:id must
 * be reachable by a fully logged-out visitor. AcceptInviteScreen does its
 * own session check inline, only for the accept action itself.
 *
 * /recovery is deliberately unguarded either way: it exists for a visitor
 * who cannot log in, so it must work regardless of session state, same as
 * its own header comment already establishes. /account/password uses
 * RequireAuth even though ChangePasswordScreen also does its own bootstrap
 * check (see that file's header comment) -- the two aren't redundant:
 * RequireAuth is what stops a genuinely logged-out visitor's browser from
 * ever mounting the screen and firing that request in the first place, and
 * ChangePasswordScreen's own check is what catches a session that expires
 * later, mid-visit, which RequireAuth cannot see, since SessionContext isn't
 * told when the server stops honoring the cookie. (RequireAuth itself
 * re-checks on every session change -- it isn't a one-time check -- but it
 * can only re-check the client state it has, not learn about an expiry the
 * server hasn't reported.)
 */
function App() {
  return (
    <SessionProvider>
      <BrowserRouter>
        <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-8">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route
              path="/signup"
              element={
                <RedirectIfAuthenticated>
                  <SignupScreen />
                </RedirectIfAuthenticated>
              }
            />
            <Route
              path="/login"
              element={
                <RedirectIfAuthenticated>
                  <LoginScreen />
                </RedirectIfAuthenticated>
              }
            />
            <Route path="/recovery" element={<RecoveryScreen />} />
            <Route
              path="/account/password"
              element={
                <RequireAuth>
                  <ChangePasswordScreen />
                </RequireAuth>
              }
            />
            <Route
              path="/groups/new"
              element={
                <RequireAuth>
                  <CreateGroupScreen />
                </RequireAuth>
              }
            />
            <Route
              path="/groups/:groupId/invite"
              element={
                <RequireAuth>
                  <CreateInviteScreen />
                </RequireAuth>
              }
            />
            <Route
              path="/groups/:groupId/settings"
              element={
                <RequireAuth>
                  <GroupSettingsScreen />
                </RequireAuth>
              }
            />
            <Route
              path="/groups/:groupId/members"
              element={
                <RequireAuth>
                  <GroupMembersScreen />
                </RequireAuth>
              }
            />
            <Route
              path="/invites"
              element={
                <RequireAuth>
                  <InvitesScreen />
                </RequireAuth>
              }
            />
            <Route path="/invites/:inviteId" element={<AcceptInviteScreen />} />
          </Routes>
        </main>
      </BrowserRouter>
    </SessionProvider>
  )
}

export default App
