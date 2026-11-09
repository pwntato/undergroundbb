// GET /api/config -- the public, unauthenticated subset of the deployment's
// runtime configuration (internal/handlers/handlers.go's publicConfig). Only
// the fields a screen reads are typed here.

import { ApiError } from './auth.js'

export interface PublicConfig {
  /** Whether a group may be set to never expire (#78). */
  readonly allowGroupExpirationOff: boolean
  /** The number of days a new group starts with. */
  readonly defaultExpirationDays: number
  readonly maxPostTitleBytes: number
  readonly maxPostBodyBytes: number
  readonly maxCommentBytes: number
}

export async function getPublicConfig(): Promise<PublicConfig> {
  const res = await fetch('/api/config', { credentials: 'same-origin' })
  if (!res.ok) {
    throw new ApiError(res.status, res.statusText || 'request failed')
  }
  return (await res.json()) as PublicConfig
}
