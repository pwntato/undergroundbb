// The signed-in user's group list, loaded once by the app shell (#47) and read by both the sidebar
// and the Home pane, so the two never disagree and the list is fetched once per navigation, not
// once per component.

import { createContext, useContext } from 'react'
import type { LoadState } from './GroupList'

export interface GroupsState {
  readonly load: LoadState
  /** Resolved usernames, for the other person of a direct message (#73), which has no name. */
  readonly usernames: ReadonlyMap<string, string>
  /** Opens the in-place password step; private group names need this tab's keys (#221). */
  readonly requestReauth: () => void
}

export const GroupsContext = createContext<GroupsState>({
  load: { status: 'loading' },
  usernames: new Map(),
  requestReauth: () => {},
})

export function useGroups(): GroupsState {
  return useContext(GroupsContext)
}
