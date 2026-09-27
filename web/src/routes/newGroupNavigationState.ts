// The shared contract between CreateGroupScreen (producer) and
// Home/runListGroups (consumer) for the GSI-eventual-consistency mitigation
// -- PR #144 review: GET /api/groups reads GSI1, which is eventually
// consistent on real DynamoDB (not reproducible against DynamoDB Local,
// which is why live-verification alone didn't catch this). A group just
// created and then immediately navigated to via navigate('/', { replace:
// true }) can be transiently missing from the very next list fetch.
//
// CreateGroupScreen already has everything needed to build a
// GroupListEntry-shaped object for the group it just created -- there is no
// need to wait for GET /api/groups to eventually reflect it. That object
// travels via react-router's navigate(..., { state }) rather than global
// state or a query param: it's relevant to exactly one navigation.
//
// This state does NOT clear itself (PR #144 round 2 review corrected an
// earlier, wrong claim here): react-router's BrowserRouter stores it in
// window.history.state.usr, which the browser keeps for as long as the
// history entry exists -- across a reload of that entry and across
// back/forward to it, not just for the one navigation that set it. Because
// CreateGroupScreen uses replace: true, the "/" entry carrying this state
// stays in history indefinitely unless something clears it. Home.tsx is
// what does that: it consumes the state once, immediately after reading it
// (navigate(location.pathname, { replace: true, state: null })), so this
// only ever affects the render right after a real creation, not every
// future visit to that same history entry. Skipping that consumption step
// is harmless only as long as the merge below dedupes by groupId against
// an already-caught-up fetch -- it stops being harmless once leave/remove-
// member exists, since a stale reload/back-forward could then resurrect a
// group the user actually left, with a stale role and an unusable key.
//
// Kept in its own module (not CreateGroupScreen.tsx or Home.tsx) so both
// sides import the same key/shape without one screen reaching into the
// other's file.

import type { GroupListEntry } from '@/lib/api/groups'

/** The react-router location.state key CreateGroupScreen sets, Home reads. */
export const NEW_GROUP_STATE_KEY = 'newGroup'

/** The shape stored under NEW_GROUP_STATE_KEY -- a full GroupListEntry for the group that was just created. */
export interface NewGroupNavigationState {
  readonly [NEW_GROUP_STATE_KEY]: GroupListEntry
}

/**
 * Narrows an arbitrary location.state value to NewGroupNavigationState's
 * own entry, or undefined if it isn't present/well-formed -- location.state
 * is `unknown` from react-router's own types (any navigate() caller can put
 * anything there), so this is the one place that trusts its shape, and only
 * after checking it actually looks like a GroupListEntry rather than
 * whatever else a future caller might one day pass through the same route.
 */
export function readNewGroupState(state: unknown): GroupListEntry | undefined {
  if (typeof state !== 'object' || state === null || !(NEW_GROUP_STATE_KEY in state)) {
    return undefined
  }
  const candidate = (state as Record<string, unknown>)[NEW_GROUP_STATE_KEY]
  if (
    typeof candidate !== 'object' ||
    candidate === null ||
    typeof (candidate as { groupId?: unknown }).groupId !== 'string' ||
    typeof (candidate as { visibility?: unknown }).visibility !== 'string' ||
    typeof (candidate as { role?: unknown }).role !== 'string' ||
    typeof (candidate as { generation?: unknown }).generation !== 'number'
  ) {
    return undefined
  }
  return candidate as GroupListEntry
}
