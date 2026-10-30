// GET /api/config -- the public, unauthenticated subset of the deployment's
// runtime configuration (internal/handlers/handlers.go's publicConfig). Only
// the fields a screen reads are typed here.

import { ApiError } from './auth.js'

export interface PublicConfig {
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
