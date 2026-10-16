// The roster's fingerprint verification controls -- issue #65. Prop-driven so it
// is tested with renderToStaticMarkup, like GroupMembersPanel.
//
// "Verified" here is a different claim from the roster's "✓ verified" role mark:
// that one says a role matches the group's signed grant history; this one says
// YOU compared this person's fingerprint out of band and it matched. The wording
// below keeps the two apart.
//
// Verification is available, not mandatory (docs/DESIGN.md): nothing is blocked
// for an unverified member, and the action is a quiet button on the row. The
// comparison itself is a prompt that shows the whole value and asks for it to be
// read out and checked group by group.

import { Button } from '@/components/ui/button'
import { FingerprintBlock } from './FingerprintBlock'
import type { MemberVerification, MemberVerifications } from './runMemberVerification'

/** The fingerprint awaiting the person's comparison, and for whom. */
export interface VerifyPrompt {
  readonly userId: string
  readonly fingerprint: string
}

export interface MemberVerificationProps {
  /** Null while loading. */
  readonly state: MemberVerifications | null
  readonly prompt: VerifyPrompt | null
  readonly onStart: (subjectUserId: string) => void
  readonly onCancel: () => void
  readonly onConfirm: (subjectUserId: string) => void
  readonly onRemove: (subjectUserId: string) => void
}

function lookup(state: MemberVerifications | null, userId: string): MemberVerification | undefined {
  return state?.state === 'ready' ? state.byUser.get(userId) : undefined
}

/** The small status next to the member's name; nothing for an ordinary unverified member. */
export function MemberVerificationBadge({
  state,
  userId,
}: {
  readonly state: MemberVerifications | null
  readonly userId: string
}) {
  const v = lookup(state, userId)
  if (v === undefined || v.verdict === 'none') {
    return null
  }
  if (v.verdict === 'verified') {
    return (
      <span
        className="text-xs text-muted-foreground"
        title="You compared their fingerprint with them, and the keys the server shows for them still give that fingerprint."
      >
        ✓ fingerprint checked by you
      </span>
    )
  }
  if (v.verdict === 'changed') {
    return (
      <span
        className="text-xs text-amber-700 dark:text-amber-400"
        title="The keys the server shows for them are not the ones you compared."
      >
        Keys changed since you checked
      </span>
    )
  }
  return (
    <span
      className="text-xs text-amber-700 dark:text-amber-400"
      title="The saved record of your check did not verify, so it is ignored."
    >
      Saved check failed
    </span>
  )
}

export function MemberVerificationControls({
  props,
  userId,
  label,
  disabled,
}: {
  readonly props: MemberVerificationProps
  readonly userId: string
  /** How the member is named in prose. */
  readonly label: string
  readonly disabled: boolean
}) {
  const { state, prompt, onStart, onCancel, onConfirm, onRemove } = props
  const v = lookup(state, userId)
  if (v === undefined) {
    return null
  }

  if (prompt?.userId === userId) {
    return (
      <span className="flex w-full flex-col gap-2">
        {v.verdict === 'changed' && (
          <span className="text-xs text-amber-700 dark:text-amber-400">
            The keys the server shows for {label} are not the ones you checked before. That can be a
            real key change or a substituted key, so compare carefully this time.
          </span>
        )}
        <span className="text-xs text-muted-foreground">
          Ask {label} to read out their fingerprint, in person or on a call you know is them. They
          can find it under &quot;Your key fingerprint&quot; on this page. Do not take it from the
          group or from a message. Check every group of digits below against what they say, not just
          the first and last.
        </span>
        <FingerprintBlock value={prompt.fingerprint} />
        <span className="flex flex-wrap gap-2">
          <Button
            type="button"
            size="sm"
            disabled={disabled}
            onClick={() => {
              onConfirm(userId)
            }}
          >
            Every group matches
          </Button>
          <Button type="button" variant="outline" size="sm" disabled={disabled} onClick={onCancel}>
            Cancel
          </Button>
        </span>
      </span>
    )
  }

  if (v.verdict === 'verified') {
    return (
      <Button
        type="button"
        variant="outline"
        size="sm"
        disabled={disabled}
        onClick={() => {
          onRemove(userId)
        }}
      >
        Remove check
      </Button>
    )
  }

  if (v.fingerprint === null) {
    return null
  }
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      disabled={disabled}
      onClick={() => {
        onStart(userId)
      }}
    >
      {v.verdict === 'none' ? 'Check fingerprint' : 'Check fingerprint again'}
    </Button>
  )
}
