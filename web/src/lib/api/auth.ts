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

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    body: JSON.stringify(body),
  })
  return handleJSON<T>(res)
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
