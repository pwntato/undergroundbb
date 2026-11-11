// What the shell's sidebar links to, and which link is the current page (#47). Pure, so the "which
// one is highlighted" rule is tested without a router.

export interface NavItem {
  readonly to: string
  readonly label: string
}

/** Places that are not one group: finding, joining and messaging. */
export const PLACE_LINKS: readonly NavItem[] = [
  { to: '/groups/new', label: 'Create a group' },
  { to: '/directory', label: 'Find groups' },
  { to: '/invites', label: 'Invites' },
  { to: '/join-requests', label: 'Join requests' },
  { to: '/dms', label: 'Direct messages' },
]

/** The account area: look, sign-in details, and the destructive end of the list. */
export const ACCOUNT_LINKS: readonly NavItem[] = [
  { to: '/appearance', label: 'Appearance' },
  { to: '/account/password', label: 'Change password' },
  { to: '/account/rotate-keys', label: 'Rotate keys' },
  { to: '/account/delete', label: 'Delete account' },
]

/** Whether `pathname` is `to` itself or a page under it (a trailing slash counts as the same). */
export function isCurrentPath(pathname: string, to: string): boolean {
  const path = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname
  return path === to || path.startsWith(`${to}/`)
}

/** Whether `pathname` is a page of this group (its posts, a thread, members, settings, ...). */
export function isCurrentGroup(pathname: string, groupId: string): boolean {
  return pathname.startsWith(`/groups/${encodeURIComponent(groupId)}/`)
}
