// The app shell's navigation (#47), hook-free so a test can render it and call its handlers: the
// signed-in user's groups (one link each, with the unread count), the places that are not a group,
// and the account links. AppShell owns the state; this owns only the markup.
//
// Below the `md` breakpoint the sidebar is a menu opened from a bar at the top. The menu button
// carries aria-expanded and names the nav it controls. Every link has a 24px rem floor (the
// linkTargets rule) and none sets its own font, so each theme's body font applies.

import { Link } from 'react-router'
import { LogoutButton } from './LogoutButton'
import type { GroupsState } from './groupsContext'
import { groupLabel } from './groupLabel'
import { PLACE_LINKS, ACCOUNT_LINKS, isCurrentGroup, isCurrentPath } from './shellNav'
import { unreadAriaLabel, unreadLabel } from './unreadLabel'

export const NAV_ID = 'app-nav'

const LINK =
  'flex min-h-[1.5rem] items-center justify-between gap-2 rounded-md px-2 py-1 text-sm [overflow-wrap:anywhere] hover:bg-accent hover:text-accent-foreground'
const CURRENT = 'bg-accent text-accent-foreground'

function NavLinkItem({
  to,
  current,
  children,
}: {
  readonly to: string
  readonly current: boolean
  readonly children: React.ReactNode
}) {
  return (
    <li>
      <Link
        to={to}
        className={current ? `${LINK} ${CURRENT}` : LINK}
        {...(current && { 'aria-current': 'page' as const })}
      >
        {children}
      </Link>
    </li>
  )
}

export interface ShellSidebarProps extends GroupsState {
  readonly pathname: string
  readonly loggingOut: boolean
  readonly logoutError: string | null
  readonly onLogout: () => Promise<void>
}

export function ShellSidebar({
  load,
  usernames,
  requestReauth,
  pathname,
  loggingOut,
  logoutError,
  onLogout,
}: ShellSidebarProps) {
  return (
    <div className="flex flex-col gap-5 p-3">
      <section aria-labelledby="nav-groups" className="flex flex-col gap-1">
        <h2 id="nav-groups" className="px-2 text-xs text-muted-foreground">
          Your groups
        </h2>
        {load.status === 'loading' && (
          <p className="px-2 text-sm text-muted-foreground">Loading your groups…</p>
        )}
        {load.status === 'error' && (
          <p className="px-2 text-sm text-destructive">
            Couldn&apos;t load your groups. Try reloading the page.
          </p>
        )}
        {load.status === 'ready' && load.groups.length === 0 && (
          <p className="px-2 text-sm text-muted-foreground">
            None yet. Create one or find one below.
          </p>
        )}
        {load.status === 'ready' && load.groups.length > 0 && (
          <ul className="flex flex-col gap-0.5">
            {load.groups.map((group) => {
              const badge = unreadLabel(group.unread, group.unreadMore)
              return (
                <NavLinkItem
                  key={group.groupId}
                  to={`/groups/${group.groupId}/posts`}
                  current={isCurrentGroup(pathname, group.groupId)}
                >
                  <span className="min-w-0">{groupLabel(group, usernames)}</span>
                  {badge !== null && (
                    <>
                      <span
                        aria-hidden="true"
                        className="shrink-0 rounded-full bg-primary px-2 py-0.5 font-mono text-xs font-normal text-primary-foreground tabular-nums"
                      >
                        {badge}
                      </span>
                      <span className="sr-only">{` (${unreadAriaLabel(badge)})`}</span>
                    </>
                  )}
                </NavLinkItem>
              )
            })}
          </ul>
        )}
        {load.status === 'ready' && load.groups.some((g) => g.nameStatus === 'coldKeys') && (
          <button
            type="button"
            onClick={requestReauth}
            className="mt-1 inline-flex min-h-[1.5rem] items-center px-2 text-left text-xs text-primary underline underline-offset-4"
          >
            Enter your password to show private group names
          </button>
        )}
      </section>

      <section aria-labelledby="nav-places" className="flex flex-col gap-1">
        <h2 id="nav-places" className="px-2 text-xs text-muted-foreground">
          Go to
        </h2>
        <ul className="flex flex-col gap-0.5">
          {PLACE_LINKS.map((item) => (
            <NavLinkItem key={item.to} to={item.to} current={isCurrentPath(pathname, item.to)}>
              {item.label}
            </NavLinkItem>
          ))}
        </ul>
      </section>

      <section aria-labelledby="nav-account" className="flex flex-col gap-1">
        <h2 id="nav-account" className="px-2 text-xs text-muted-foreground">
          Account
        </h2>
        <ul className="flex flex-col gap-0.5">
          {ACCOUNT_LINKS.map((item) => (
            <NavLinkItem key={item.to} to={item.to} current={isCurrentPath(pathname, item.to)}>
              {item.label}
            </NavLinkItem>
          ))}
        </ul>
        <div className="px-2 pt-1">
          <LogoutButton loggingOut={loggingOut} onLogout={onLogout} />
        </div>
        {logoutError !== null && <p className="px-2 text-sm text-destructive">{logoutError}</p>}
      </section>
    </div>
  )
}

/** The frame: a top bar with the menu button below `md`, the nav, then the page. */
export function ShellFrame({
  open,
  onToggle,
  sidebar,
  children,
}: {
  readonly open: boolean
  readonly onToggle: () => void
  readonly sidebar: React.ReactNode
  readonly children: React.ReactNode
}) {
  return (
    <div className="flex min-h-screen flex-col md:flex-row">
      <div className="flex min-h-12 items-center border-b border-border px-3 md:hidden">
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          aria-controls={NAV_ID}
          className="inline-flex min-h-[2.5rem] items-center rounded-md border border-border px-3 text-sm"
        >
          {open ? 'Close menu' : 'Menu'}
        </button>
      </div>
      <nav
        id={NAV_ID}
        aria-label="Main"
        className={`${open ? 'block' : 'hidden'} border-b border-border bg-card text-card-foreground md:sticky md:top-0 md:block md:h-screen md:w-64 md:shrink-0 md:overflow-y-auto md:border-b-0 md:border-r`}
      >
        {sidebar}
      </nav>
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  )
}
