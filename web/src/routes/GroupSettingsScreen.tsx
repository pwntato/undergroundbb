// #36: group detail and settings screen at /groups/:groupId/settings.
// Wrapped by RequireAuth in App.tsx (baseline session check; the server
// decides who may see or edit a given group, and its 404/403 are this
// screen's real authorization, the same split CreateInviteScreen has).
//
// Loading and saving are runGroupSettings.ts's job; this component owns
// state and effects, and GroupSettingsPanel owns rendering.

import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { getGroup, updateGroup } from '@/lib/api/groups'
import { decryptGroupNames, encryptGroupText } from '@/lib/crypto/worker-client'
import { getCachedGroupName, setCachedGroupName } from '@/lib/groups/groupNameCache'
import { useSession } from '@/lib/session/useSession'
import { GroupSettingsPanel } from './GroupSettingsPanel'
import {
  loadGroupSettings,
  saveGroupSettings,
  type SaveSettingsResult,
  type SettingsForm,
  type SettingsView,
} from './runGroupSettings'

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly view: SettingsView }
  | { readonly status: 'notFound' | 'authRequired' | 'failed' }

const SAVE_ERRORS: Record<Exclude<SaveSettingsResult, { ok: true }>['kind'], string> = {
  versionConflict:
    'Someone else changed this group while you were editing. The latest settings are shown; reapply your changes.',
  forbidden: 'Only a group admin can edit these settings.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'Log in again to edit this private group.',
  notFound: 'This group no longer exists, or you are no longer a member.',
  rejected: 'The server rejected these changes.',
  ambiguous:
    "We couldn't confirm whether your changes were saved. Reload to check before trying again.",
}

export function GroupSettingsScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  const session = useSession()
  const userId = session.userId
  const [load, setLoad] = useState<LoadState>({ status: 'loading' })
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  const reload = useCallback(
    async (isCancelled: () => boolean) => {
      if (groupId === undefined || userId === null) {
        return
      }
      const result = await loadGroupSettings(
        { getGroup, decryptGroupNames, getCachedGroupName, setCachedGroupName, userId },
        groupId,
      )
      if (isCancelled()) {
        return
      }
      setLoad(result.ok ? { status: 'ready', view: result.view } : { status: result.kind })
    },
    [groupId, userId],
  )

  useEffect(() => {
    let cancelled = false
    void (async () => {
      await reload(() => cancelled)
    })()
    return () => {
      cancelled = true
    }
  }, [reload])

  if (groupId === undefined) {
    return (
      <Alert variant="destructive">
        <AlertDescription>Missing group id.</AlertDescription>
      </Alert>
    )
  }

  const handleSave = (form: SettingsForm) => {
    if (load.status !== 'ready' || userId === null) {
      return
    }
    const { view } = load
    setSaving(true)
    setMessage(null)
    setError(null)
    void (async () => {
      const outcome = await saveGroupSettings(
        { updateGroup, encryptGroupText, setCachedGroupName, userId },
        view,
        form,
      )
      setSaving(false)
      if (outcome.ok) {
        setMessage('Saved.')
      } else {
        setError(outcome.kind === 'rejected' ? outcome.message : SAVE_ERRORS[outcome.kind])
      }
      // Reload after a success (to pick up the new version) and after a
      // conflict (to show the other admin's values). Not after an
      // ambiguous failure: the user is told to reload deliberately.
      if (outcome.ok || outcome.kind === 'versionConflict') {
        await reload(() => false)
      }
    })()
  }

  return (
    <>
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'notFound' && (
        <p className="text-sm text-muted-foreground">
          This group doesn&apos;t exist, or you&apos;re not a member of it.
        </p>
      )}
      {load.status === 'authRequired' && (
        <p className="text-sm text-destructive">Your session has expired. Log in again.</p>
      )}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">
          Couldn&apos;t load this group. Try reloading the page.
        </p>
      )}
      {load.status === 'ready' && (
        <GroupSettingsPanel
          // Re-mount on a new version so the form fields reset to what the
          // server now holds (after a save or a conflict).
          key={load.view.detail.version}
          view={load.view}
          onSave={handleSave}
          saving={saving}
          message={message}
          error={error}
        />
      )}
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}
