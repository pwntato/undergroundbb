// Home's "Log out" button, split out so a test can call it as a plain function and check the two
// things the click handler's own tests cannot: it is disabled while a logout is in flight (no
// second request), and its click calls the handler.

import { Button } from '@/components/ui/button'

export function LogoutButton({
  loggingOut,
  onLogout,
}: {
  readonly loggingOut: boolean
  readonly onLogout: () => Promise<void>
}) {
  return (
    <Button variant="outline" disabled={loggingOut} onClick={() => void onLogout()}>
      Log out
    </Button>
  )
}
