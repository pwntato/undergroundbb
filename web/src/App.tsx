import { BrowserRouter, Route, Routes } from 'react-router'
import { ChangePasswordScreen } from '@/routes/ChangePasswordScreen'
import { Home } from '@/routes/Home'
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
 * screen; #32 adds the session bootstrap and the guards below; everything
 * else this milestone needs (the board views, etc.) arrives with the
 * features that need them.
 *
 * /recovery is deliberately unguarded either way: it exists for a visitor
 * who cannot log in, so it must work regardless of session state, same as
 * its own header comment already establishes. /account/password uses
 * RequireAuth even though ChangePasswordScreen also does its own bootstrap
 * check (see that file's header comment) -- the two aren't redundant:
 * RequireAuth is what stops a genuinely logged-out visitor's browser from
 * ever mounting the screen and firing that request in the first place, and
 * ChangePasswordScreen's own check is what catches a session that expires
 * later, mid-visit, which RequireAuth (checked once, on mount) cannot.
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
          </Routes>
        </main>
      </BrowserRouter>
    </SessionProvider>
  )
}

export default App
