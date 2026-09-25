// Typed client for the unauthenticated auth endpoints -- see
// internal/handlers/{register,login,username_available}.go for the server
// side of every shape here. Every binary field crosses the wire as
// standard-padded base64, matching decodeBase64Field's own expectation.

export interface WireArgon2Params {
  readonly memoryKiB: number
  readonly iterations: number
  readonly parallelism: number
}

export interface WireWrappedBlob {
  readonly nonce: string
  readonly ciphertext: string
}

/** ApiError carries the HTTP status alongside the server's error message. */
export class ApiError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function sendJSON<T>(method: 'POST' | 'PUT', path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  })
  return handleJSON<T>(res)
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  return sendJSON<T>('POST', path, body)
}

async function handleJSON<T>(res: Response): Promise<T> {
  let data: unknown
  try {
    data = await res.json()
  } catch {
    throw new ApiError(res.status, res.statusText || 'malformed response')
  }
  if (!res.ok) {
    const message =
      typeof data === 'object' && data !== null && 'error' in data && typeof data.error === 'string'
        ? data.error
        : res.statusText || 'request failed'
    throw new ApiError(res.status, message)
  }
  return data as T
}

/** GET /api/auth/username-available?u=<name> -- advisory only, see the handler's own doc comment. */
export async function usernameAvailable(username: string): Promise<boolean> {
  const res = await fetch(`/api/auth/username-available?u=${encodeURIComponent(username)}`, {
    credentials: 'same-origin',
  })
  const data = await handleJSON<{ available: boolean }>(res)
  return data.available
}

export interface RegisterRequest {
  readonly username: string
  /**
   * Client-generated (see crypto/uuid.ts), not server-assigned -- issue
   * #123. The credential-wrap AAD binds this uuid into wrappedPrivateKeys/
   * recoveryWrappedPrivateKeys before this request is ever sent, so the
   * client must already know it at wrap time.
   */
  readonly userId: string
  readonly signingPublicKey: string
  readonly wrappingPublicKey: string
  readonly salt: string
  readonly argon2Params: WireArgon2Params
  readonly wrappedPrivateKeys: WireWrappedBlob
  readonly recoverySalt: string
  readonly recoveryArgon2Params: WireArgon2Params
  readonly recoveryWrappedPrivateKeys: WireWrappedBlob
  readonly recoveryVerifierSalt: string
  readonly recoveryVerifierParams: WireArgon2Params
  readonly recoveryVerifier: string
}

export interface RegisterResponse {
  readonly userId: string
}

/** POST /api/auth/register. Throws ApiError(409) if the username is taken. */
export async function register(req: RegisterRequest): Promise<RegisterResponse> {
  return postJSON<RegisterResponse>('/api/auth/register', req)
}

export interface ChallengeResponse {
  readonly nonce: string
  readonly userId: string
  readonly salt: string
  readonly argon2Params: WireArgon2Params
  readonly wrappedPrivateKeys: WireWrappedBlob
}

/**
 * POST /api/auth/challenge -- login step 1-2. Always resolves, even for an
 * unknown username (see the handler's own doc comment on why: the response
 * is plausible-shaped filler that cannot complete a login).
 */
export async function challenge(username: string): Promise<ChallengeResponse> {
  return postJSON<ChallengeResponse>('/api/auth/challenge', { username })
}

export interface VerifyResponse {
  readonly userId: string
  readonly credentialVersion: number
}

/**
 * POST /api/auth/verify -- login step 4. On success, the server also sets
 * the session cookie via Set-Cookie; nothing here reads or stores it, since
 * it is HttpOnly.
 */
export async function verify(
  username: string,
  nonce: string,
  signature: string,
): Promise<VerifyResponse> {
  return postJSON<VerifyResponse>('/api/auth/verify', { username, nonce, signature })
}

export interface RecoveryCodeReleaseResponse {
  readonly credentialVersion: number
  readonly userId: string
  readonly salt: string
  readonly argon2Params: WireArgon2Params
  readonly wrappedPrivateKeys: WireWrappedBlob
}

/**
 * POST /api/account/recovery-code/release -- #31/#128, recovery step 1.
 * Unauthenticated: a user recovering has no session. Always fails the same
 * way (ApiError 401, "invalid username or recovery code") for an unknown
 * username, a wrong code, or a user with no RECOVERY item at all -- see
 * internal/handlers/recovery.go's resolveRecovery, the same
 * enumeration-resistance reasoning challenge() already relies on for login.
 */
export async function recoveryCodeRelease(
  username: string,
  recoveryCode: string,
): Promise<RecoveryCodeReleaseResponse> {
  return postJSON<RecoveryCodeReleaseResponse>('/api/account/recovery-code/release', {
    username,
    recoveryCode,
  })
}

export interface RecoveryCodeResetRequest {
  readonly username: string
  readonly recoveryCode: string
  readonly expectedCredentialVersion: number
  /**
   * A random value runRecovery.ts generates once per reset attempt and
   * resends unchanged on a retry -- see recovery.go's own doc comment on
   * recoveryCodeReset for why this is what lets a retry whose response was
   * lost be recognized as such, rather than rejected as a wrong code
   * (issue #130). Optional at the wire level; omitted entirely rather than
   * sent empty when a caller has none to offer.
   */
  readonly idempotencyToken?: string
  readonly salt: string
  readonly argon2Params: WireArgon2Params
  readonly wrappedPrivateKeys: WireWrappedBlob
  readonly recoverySalt: string
  readonly recoveryArgon2Params: WireArgon2Params
  readonly recoveryWrappedPrivateKeys: WireWrappedBlob
  readonly recoveryVerifierSalt: string
  readonly recoveryVerifierParams: WireArgon2Params
  readonly recoveryVerifier: string
}

export interface RecoveryCodeResetResponse {
  readonly credentialVersion: number
}

/**
 * PUT /api/account/recovery-code -- #31/#128, recovery step 2. Re-checks
 * username + recoveryCode against the verifier itself (independent of the
 * earlier release() call, per recovery.go's own doc comment: the verifier
 * is what authorizes this write, not a token minted by release). Throws
 * ApiError(409) if expectedCredentialVersion is stale -- e.g. a concurrent
 * change-password or a second recovery attempt from another tab -- the
 * same conflict changePassword's own PUT would raise.
 */
export async function recoveryCodeReset(
  req: RecoveryCodeResetRequest,
): Promise<RecoveryCodeResetResponse> {
  return sendJSON<RecoveryCodeResetResponse>('PUT', '/api/account/recovery-code', req)
}

export interface AccountCredentialsResponse {
  readonly userId: string
  readonly salt: string
  readonly argon2Params: WireArgon2Params
  readonly wrappedPrivateKeys: WireWrappedBlob
  readonly credentialVersion: number
}

/**
 * GET /api/account/credentials -- #131, change-password step 1.
 * Authenticated by the session cookie; the change-password screen's own
 * bootstrap, since GET /api/auth/session (the other authenticated
 * account-state read) only returns userId, not the salt/argon2Params/
 * wrappedPrivateKeys a client needs to unwrap PROFILE with the old
 * password. userId is included here too (not just relying on
 * SessionContext's) since SessionContext's own doc comment says its userId
 * does not survive a page reload -- this response is this screen's only
 * reliable source for it. Throws ApiError(401) if there is no valid
 * session.
 */
export async function getAccountCredentials(): Promise<AccountCredentialsResponse> {
  const res = await fetch('/api/account/credentials', { credentials: 'same-origin' })
  return handleJSON<AccountCredentialsResponse>(res)
}

export interface ChangePasswordRequest {
  readonly expectedCredentialVersion: number
  readonly salt: string
  readonly argon2Params: WireArgon2Params
  readonly wrappedPrivateKeys: WireWrappedBlob
  readonly recoverySalt: string
  readonly recoveryArgon2Params: WireArgon2Params
  readonly recoveryWrappedPrivateKeys: WireWrappedBlob
  readonly recoveryVerifierSalt: string
  readonly recoveryVerifierParams: WireArgon2Params
  readonly recoveryVerifier: string
}

export interface ChangePasswordResponse {
  readonly credentialVersion: number
}

/**
 * PUT /api/account/password -- #30/#131, change-password step 2.
 * Authenticated by the session cookie; re-checks nothing about the old
 * password server-side (password.go's changePassword's own doc comment --
 * the client proves it by having successfully unwrapped PROFILE, not by
 * anything this request carries). Throws ApiError(409) if
 * expectedCredentialVersion is stale -- the same conflict
 * recoveryCodeReset's own PUT can raise.
 */
export async function changePassword(req: ChangePasswordRequest): Promise<ChangePasswordResponse> {
  return sendJSON<ChangePasswordResponse>('PUT', '/api/account/password', req)
}
