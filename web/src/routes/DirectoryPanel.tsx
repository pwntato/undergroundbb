// The presentational half of the public group directory (#71): a search form and one row per public
// group. Prop-driven, no effects, so it tests with renderToStaticMarkup and by calling it as a function.
// Names are not unique, so every row carries the start of its group id and its description: two rows
// reading "Book Club" are correct output.

import { Link } from 'react-router'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { snippet, type DirectoryRow } from './directoryRows'

export function DirectoryPanel({
  query,
  rows,
  searched,
  hasMore,
  busy,
  onQueryChange,
  onSearch,
  onLoadMore,
}: {
  readonly query: string
  readonly rows: readonly DirectoryRow[]
  /** The query the shown rows are for ('' when browsing), so an empty result can say what it searched. */
  readonly searched: string
  readonly hasMore: boolean
  readonly busy: boolean
  readonly onQueryChange: (q: string) => void
  readonly onSearch: () => void
  readonly onLoadMore: () => void
}) {
  return (
    <div className="flex w-full max-w-md flex-col gap-3">
      <form
        className="flex gap-2"
        onSubmit={(e) => {
          e.preventDefault()
          onSearch()
        }}
      >
        <Input
          aria-label="Group name starts with"
          placeholder="Name starts with…"
          value={query}
          maxLength={200}
          onChange={(e) => {
            onQueryChange(e.target.value)
          }}
        />
        <Button type="submit" disabled={busy}>
          {busy ? 'Searching…' : 'Search'}
        </Button>
      </form>
      <p className="text-xs text-muted-foreground">
        Public groups show their name and description to everyone; their posts and members stay
        private. Search matches the start of a name, capital letters included.
      </p>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          {searched === ''
            ? 'No public groups yet.'
            : `No public group has a name starting with "${searched}".`}
        </p>
      ) : (
        <ul className="flex flex-col gap-2">
          {rows.map((row) => (
            <li key={row.entry.groupId} className="flex flex-col gap-1 rounded-md border px-3 py-2">
              <span className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1">
                <span className="min-w-0 [overflow-wrap:anywhere]">
                  <span className="font-medium">{row.entry.name}</span>
                  <span className="block font-mono text-xs text-muted-foreground">
                    #{row.shortId}
                  </span>
                </span>
                <RowAction row={row} />
              </span>
              {snippet(row.entry.description) !== '' && (
                <span className="text-xs text-muted-foreground [overflow-wrap:anywhere]">
                  {snippet(row.entry.description)}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {hasMore && (
        <Button type="button" variant="outline" size="sm" disabled={busy} onClick={onLoadMore}>
          Show more
        </Button>
      )}
    </div>
  )
}

function RowAction({ row }: { readonly row: DirectoryRow }) {
  const linkClass = 'text-xs text-primary underline-offset-4 hover:underline'
  switch (row.status.kind) {
    case 'member':
      return <span className="text-xs text-muted-foreground">You are a member</span>
    case 'pending':
      return (
        <Link to="/join-requests" className={linkClass}>
          Request waiting
        </Link>
      )
    case 'declined':
      return (
        <span className="text-xs text-muted-foreground">
          Declined
          {row.status.retryAfter !== undefined && `, ask again after ${row.status.retryAfter}`}
        </span>
      )
    case 'available':
      return (
        <Link to={`/groups/${row.entry.groupId}/join`} className={linkClass}>
          Ask to join
        </Link>
      )
  }
}
