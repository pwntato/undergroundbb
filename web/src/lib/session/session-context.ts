import { createContext } from 'react'

export interface SessionState {
  /**
   * 'loading' until the GET /api/auth/session bootstrap (issue #32) resolves
   * once on app mount, then 'ready' for the rest of the tab's life. userId
   * is only meaningful once status is 'ready' -- while 'loading', it's
   * always null, whether or not a session cookie actually exists, so a
   * consumer that branches on userId alone before checking status would
   * momentarily render as logged-out even for an authenticated visitor.
   */
  readonly status: 'loading' | 'ready'
  readonly userId: string | null
  readonly login: (userId: string) => void
  readonly logout: () => void
}

export const SessionContext = createContext<SessionState | undefined>(undefined)
