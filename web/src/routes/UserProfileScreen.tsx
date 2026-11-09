// #75: a user's profile at /users/:userId, wrapped by RequireAuth in App.tsx.
// It reads the same projection every signed-in user can read
// (GET /api/users/:id), computes the fingerprint locally from the served keys,
// and, for someone else, shows the caller's own verification state. The owner
// edits their bio here. There is no cross-group post feed on purpose: a viewer
// holds keys only for their own groups, and an author-to-content index is the
// queryable map the metadata design avoids.

import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router'
import { ApiError } from '@/lib/api/auth'
import { getUser, getUsers, putBio } from '@/lib/api/users'
import { listAllVerifications } from '@/lib/api/verifications'
import { getOwnSigningKey } from '@/lib/crypto/worker-client'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { useSession } from '@/lib/session/useSession'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { profileView, type ProfileView } from './profileView'
import { loadMemberVerifications, type MemberVerifications } from './runMemberVerification'
import { SAVE_BIO_ERRORS, saveBio } from './runSaveBio'
import { UserProfilePanel } from './UserProfilePanel'

type LoadState =
  | { readonly status: 'loading' }
  | { readonly status: 'ready'; readonly view: ProfileView }
  | { readonly status: 'notFound' | 'authRequired' | 'failed' }

// Keyed by user: the screen is reused when :userId changes, and the drafts and
// messages below belong to exactly one profile.
export function UserProfileScreen() {
  const { userId } = useParams<{ userId: string }>()
  return <UserProfile key={userId ?? ''} profileUserId={userId} />
}

function UserProfile({ profileUserId }: { readonly profileUserId: string | undefined }) {
  const session = useSession()
  const selfId = session.userId
  const [load, setLoad] = useState<LoadState>(
    profileUserId === undefined ? { status: 'notFound' } : { status: 'loading' },
  )
  const [verification, setVerification] = useState<MemberVerifications | null>(null)
  const [draft, setDraft] = useState('')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const isSelf = selfId !== null && selfId === profileUserId

  useEffect(() => {
    if (profileUserId === undefined) return
    let cancelled = false
    void (async () => {
      try {
        const user = await getUser(profileUserId)
        if (cancelled) return
        const view = profileView(user)
        setDraft(view.bio)
        setLoad({ status: 'ready', view })
      } catch (e) {
        if (cancelled) return
        if (e instanceof ApiError && e.status === 404) setLoad({ status: 'notFound' })
        else if (e instanceof ApiError && e.status === 401) setLoad({ status: 'authRequired' })
        else setLoad({ status: 'failed' })
      }
    })()
    return () => {
      cancelled = true
    }
  }, [profileUserId])

  useEffect(() => {
    if (selfId === null || profileUserId === undefined || profileUserId === selfId) return
    let cancelled = false
    void (async () => {
      const result = await loadMemberVerifications(
        {
          getUsers,
          listVerifications: listAllVerifications,
          ownSigningKey: () => ownSigningKeyWithFallback(selfId, getOwnSigningKey),
          loadOwnKeyHistory: makeOwnKeyHistoryLoader(selfId),
          selfUserId: selfId,
        },
        [profileUserId],
      )
      if (!cancelled) setVerification(result)
    })()
    return () => {
      cancelled = true
    }
  }, [selfId, profileUserId])

  const handleSave = useCallback(async () => {
    setSaving(true)
    setError(null)
    setMessage(null)
    const result = await saveBio({ putBio }, draft)
    setSaving(false)
    if (!result.ok) {
      setError(SAVE_BIO_ERRORS[result.kind])
      return
    }
    setDraft(result.bio)
    setLoad((prev) =>
      prev.status === 'ready' ? { status: 'ready', view: { ...prev.view, bio: result.bio } } : prev,
    )
    setMessage(result.bio === '' ? 'Bio cleared.' : 'Saved.')
  }, [draft])

  return (
    <main className="flex min-h-svh flex-col items-center gap-4 p-6">
      {load.status === 'loading' && <p className="text-sm text-muted-foreground">Loading…</p>}
      {load.status === 'notFound' && (
        <p className="text-sm text-destructive">This user doesn&apos;t exist.</p>
      )}
      {load.status === 'authRequired' && (
        <p className="text-sm text-destructive">Your session has expired. Log in again.</p>
      )}
      {load.status === 'failed' && (
        <p className="text-sm text-destructive">
          Couldn&apos;t load this profile. Try reloading the page.
        </p>
      )}
      {load.status === 'ready' && (
        <UserProfilePanel
          view={load.view}
          isSelf={isSelf}
          verification={verification}
          bioEdit={
            isSelf
              ? {
                  draft,
                  onDraftChange: setDraft,
                  onSave: () => {
                    void handleSave()
                  },
                  saving,
                  message,
                  error,
                }
              : undefined
          }
        />
      )}
    </main>
  )
}
