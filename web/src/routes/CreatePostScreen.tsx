// #42: write a post at /groups/:groupId/posts/new. Wrapped by RequireAuth in
// App.tsx (baseline session check; the server's 404/409 are the real checks).
//
// Sealing and sending are runCreatePost.ts's job; this component owns state and
// effects, and CreatePostPanel owns rendering. A post whose send got no answer
// is kept sealed and sent again byte for byte, so a lost response can never
// become two posts.

import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { getPublicConfig } from '@/lib/api/config'
import { createPost, getGroup, getKeychain } from '@/lib/api/groups'
import { sealPost } from '@/lib/crypto/worker-client'
import type { SealedPost } from '@/lib/crypto/worker-protocol'
import { fetchNameChain } from '@/lib/groups/nameChain'
import { useSession } from '@/lib/session/useSession'
import { CreatePostPanel } from './CreatePostPanel'
import { ReauthenticateStep } from './ReauthenticateStep'
import {
  DEFAULT_POST_LIMITS,
  FORM_PROBLEMS,
  preparePost,
  sendPost,
  type PostLimits,
  type PrepareResult,
  type SendResult,
} from './runCreatePost'

const PREPARE_ERRORS: Record<Exclude<PrepareResult, { ok: true }>['kind'], string> = {
  invalid: 'Check the form and try again.',
  notFound: 'This group no longer exists, or you are no longer a member.',
  authRequired: 'Your session has expired. Log in again and retry.',
  coldKeys: 'This tab needs your password again to write a post.',
  behind:
    'Your key for this group is behind. Wait for the key rotation to reach you (an admin finishes it from Members), then try again.',
  unreadable:
    "Couldn't open this group's key, so the post was not written. Reload the page and try again.",
  failed: "Couldn't load this group. Try again.",
}

const SEND_ERRORS: Record<Exclude<SendResult, { ok: true }>['kind'], string> = {
  reseal: 'The group changed while you were writing. Press Post again to send it with the new key.',
  behind:
    'Your key for this group is behind. Wait for the key rotation to reach you, then try again.',
  dormant:
    'You rotated your keys and an admin has not approved them for this group yet. Ask an admin to approve you from Members.',
  authRequired: 'Your session has expired. Log in again and retry.',
  notFound: 'This group no longer exists, or you are no longer a member.',
  rejected: 'The server rejected the post.',
  ambiguous:
    "We couldn't confirm whether the post was saved. Press Post again to send the same post; it will not be posted twice.",
}

export function CreatePostScreen() {
  const { groupId } = useParams<{ groupId: string }>()
  const session = useSession()
  const userId = session.userId
  const [limits, setLimits] = useState<PostLimits>(DEFAULT_POST_LIMITS)
  const [posting, setPosting] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [needsReauth, setNeedsReauth] = useState(false)
  // Bumped after a success so the form remounts empty.
  const [round, setRound] = useState(0)
  // The post a send left unanswered, with the form text it came from; sent
  // again unchanged while the text still matches.
  const pending = useRef<{ sealed: SealedPost; title: string; body: string } | null>(null)

  useEffect(() => {
    let cancelled = false
    void getPublicConfig()
      .then((c) => {
        if (!cancelled) {
          setLimits({ maxTitleBytes: c.maxPostTitleBytes, maxBodyBytes: c.maxPostBodyBytes })
        }
      })
      .catch(() => {
        // The defaults match the server's; it enforces its own limit regardless.
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (groupId === undefined) {
    return (
      <Alert variant="destructive">
        <AlertDescription>Missing group id.</AlertDescription>
      </Alert>
    )
  }

  const handleSubmit = (title: string, body: string) => {
    if (userId === null) {
      return
    }
    setPosting(true)
    setMessage(null)
    setError(null)
    void (async () => {
      let sealed: SealedPost
      const again = pending.current
      if (again !== null && again.title === title && again.body === body) {
        sealed = again.sealed
      } else {
        pending.current = null
        const prepared = await preparePost(
          {
            getGroup,
            getChain: (gid, from, to) => fetchNameChain(getKeychain, gid, from, to),
            sealPost,
            userId,
          },
          groupId,
          title,
          body,
          limits,
        )
        if (!prepared.ok) {
          setPosting(false)
          if (prepared.kind === 'invalid' && prepared.problem !== undefined) {
            setError(FORM_PROBLEMS[prepared.problem])
          } else {
            setError(PREPARE_ERRORS[prepared.kind])
          }
          if (prepared.kind === 'coldKeys') {
            setNeedsReauth(true)
          }
          return
        }
        sealed = prepared.sealed
      }
      const sent = await sendPost({ createPost }, groupId, sealed)
      setPosting(false)
      if (sent.ok) {
        pending.current = null
        setMessage('Posted.')
        setRound((n) => n + 1)
        return
      }
      pending.current = sent.kind === 'ambiguous' ? { sealed, title, body } : null
      setError(
        sent.kind === 'rejected' ? (sent.message ?? SEND_ERRORS.rejected) : SEND_ERRORS[sent.kind],
      )
    })()
  }

  if (needsReauth && userId !== null) {
    return (
      <ReauthenticateStep
        sessionUserId={userId}
        action="write a post"
        onDone={() => {
          setNeedsReauth(false)
          setError(null)
        }}
        onCancel={() => {
          setNeedsReauth(false)
        }}
      />
    )
  }

  return (
    <>
      <h1 className="text-lg font-semibold">New post</h1>
      <CreatePostPanel
        key={round}
        limits={limits}
        posting={posting}
        message={message}
        error={error}
        onSubmit={handleSubmit}
      />
      <Link to="/" className="text-sm text-primary underline-offset-4 hover:underline">
        Back to your groups
      </Link>
    </>
  )
}
