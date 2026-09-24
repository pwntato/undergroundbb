import { BrowserRouter, Route, Routes } from 'react-router'
import { Home } from '@/routes/Home'
import { LoginScreen } from '@/routes/LoginScreen'
import { RecoveryScreen } from '@/routes/RecoveryScreen'
import { SignupScreen } from '@/routes/SignupScreen'
import { SessionProvider } from '@/lib/session/SessionContext'

/**
 * Application shell: session state + routing. #33 adds the first real
 * screens (signup, login) on top of the placeholder scaffold; #128 adds
 * recovery; everything else this milestone needs (the board views, etc.)
 * arrives with the features that need them.
 */
function App() {
  return (
    <SessionProvider>
      <BrowserRouter>
        <main className="flex min-h-screen flex-col items-center justify-center gap-4 p-8">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/signup" element={<SignupScreen />} />
            <Route path="/login" element={<LoginScreen />} />
            <Route path="/recovery" element={<RecoveryScreen />} />
          </Routes>
        </main>
      </BrowserRouter>
    </SessionProvider>
  )
}

export default App
