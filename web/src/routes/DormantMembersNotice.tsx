// The roster's notice for members who changed their keys (#62): their entry in
// this group is still wrapped to the key they replaced, so they cannot read new
// content until an admin or ambassador approves the new keys. Prop-driven and
// read-only, tested with renderToStaticMarkup like the rest of the roster.

import { Alert, AlertDescription } from '@/components/ui/alert'
import type { Dormancy, DormantMember } from './dormancy'
import { memberLabel } from './memberLabel'

const ENTRY_NOTE: Record<DormantMember['entry'], string> = {
  behind:
    'The group has moved on to a newer key since they changed theirs, so approving them wraps the current key to their new one.',
  current:
    'They are still on the group’s current key, so the keys they replaced can still read it. Approving them means a new key for the whole group.',
}

export function DormantMembersNotice({
  dormancy,
  usernames,
}: {
  /** Null while loading. */
  readonly dormancy: Dormancy | null
  readonly usernames: ReadonlyMap<string, string>
}) {
  if (dormancy === null) {
    return null
  }
  if (dormancy.state === 'unavailable') {
    return (
      <p className="text-xs text-muted-foreground">
        Couldn&apos;t check which members changed their keys, so none are flagged. A member who did
        looks the same as any other until this loads. Reload to try again.
      </p>
    )
  }
  if (dormancy.dormant.length === 0) {
    return null
  }
  return (
    <Alert>
      <AlertDescription className="flex flex-col gap-3">
        <span className="font-medium">
          {dormancy.dormant.length === 1
            ? '1 member changed their keys'
            : `${String(dormancy.dormant.length)} members changed their keys`}
        </span>
        <span className="text-xs">
          They stay in the group but cannot read new content here until an admin or ambassador
          approves their new keys. Check the fingerprint with them in person or on a call you know
          is them. Do not take it from the group or from a message.
        </span>
        <ul className="flex flex-col gap-3">
          {dormancy.dormant.map((d) => (
            <li key={d.userId} className="flex flex-col gap-1">
              <span className="text-sm">{memberLabel(d.userId, usernames)}</span>
              <span className="text-xs text-muted-foreground">{ENTRY_NOTE[d.entry]}</span>
              {d.fingerprint === null ? (
                <span className="text-xs text-amber-700 dark:text-amber-400">
                  Their keys could not be read, so there is no fingerprint to check.
                </span>
              ) : (
                <span className="font-mono text-xs break-all">{d.fingerprint}</span>
              )}
            </li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  )
}
