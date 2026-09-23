import { createContext } from 'react'

export interface SessionState {
  readonly userId: string | null
  readonly login: (userId: string) => void
  readonly logout: () => void
}

export const SessionContext = createContext<SessionState | undefined>(undefined)
