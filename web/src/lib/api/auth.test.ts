// Every other consumer in this codebase tests against auth.ts's exported
// request functions (register/challenge/verify/...) by injecting them as
// already-resolved/rejected promises -- see runSignup.test.ts's own header.
// That convention doesn't reach handleJSON itself, the one place that
// parses an error response body into an ApiError, which is exactly what
// issue #134's fix depends on (ApiError.code, read from the server's
// `code` field). This is the one direct test of that parsing, via a
// stubbed global fetch against register() -- the real caller #134's fix
// actually needs the `code` field from.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError, getSession, register } from './auth'

const VALID_REGISTER_REQUEST = {
  username: 'alice',
  userId: 'user-1',
  signingPublicKey: 'c2lnbmluZw==',
  wrappingPublicKey: 'd3JhcHBpbmc=',
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
  recoverySalt: 'cmVjb3Zlcnktc2FsdA==',
  recoveryArgon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryWrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'cmVjb3Zlcnktc2FsdA==' },
  recoveryVerifierSalt: 'dmVyaWZpZXItc2FsdA==',
  recoveryVerifierParams: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryVerifier: 'dmVyaWZpZXI=',
}

function stubFetch(status: number, body: unknown) {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: status >= 200 && status < 300,
      status,
      statusText: '',
      json: () => Promise.resolve(body),
    }),
  )
}

describe('ApiError.code (issue #134)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('is set from the response body’s "code" field on a WriteErrorWithCode response', async () => {
    stubFetch(409, { error: 'username is taken', code: 'username_taken' })

    await expect(register(VALID_REGISTER_REQUEST)).rejects.toMatchObject({
      status: 409,
      message: 'username is taken',
      code: 'username_taken',
    })
  })

  it('is undefined on a plain WriteError response with no "code" field', async () => {
    stubFetch(400, { error: 'username: must be 3-32 characters' })

    let caught: unknown
    try {
      await register(VALID_REGISTER_REQUEST)
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(ApiError)
    expect((caught as ApiError).code).toBeUndefined()
  })

  it('is undefined when the response body has no JSON at all', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 500,
        statusText: 'Internal Server Error',
        json: () => Promise.reject(new Error('not json')),
      }),
    )

    let caught: unknown
    try {
      await register(VALID_REGISTER_REQUEST)
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(ApiError)
    expect((caught as ApiError).status).toBe(500)
    expect((caught as ApiError).code).toBeUndefined()
  })

  it('ignores a non-string "code" field rather than propagating a malformed value', async () => {
    stubFetch(409, { error: 'username is taken', code: 12345 })

    let caught: unknown
    try {
      await register(VALID_REGISTER_REQUEST)
    } catch (err) {
      caught = err
    }
    expect(caught).toBeInstanceOf(ApiError)
    expect((caught as ApiError).code).toBeUndefined()
  })
})

describe('getSession (issue #32)', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('resolves authenticated: true with a userId when a valid session cookie is present', async () => {
    stubFetch(200, { authenticated: true, userId: 'user-1' })

    await expect(getSession()).resolves.toEqual({ authenticated: true, userId: 'user-1' })
  })

  it('resolves authenticated: false, not a thrown ApiError, when there is no session', async () => {
    // Matches getSession's own server-side handler: a missing or invalid
    // cookie is always a 200 with authenticated: false, never a 401 -- this
    // endpoint exists specifically for a caller that doesn't yet know
    // whether it has a session (see internal/handlers/session.go's own doc
    // comment on getSession).
    stubFetch(200, { authenticated: false })

    await expect(getSession()).resolves.toEqual({ authenticated: false })
  })
})
