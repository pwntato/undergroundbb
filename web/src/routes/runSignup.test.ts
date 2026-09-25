// Pins issue #124's client-side half, and PR #133 round 1's correction of
// it: a resubmission of the SAME username AND password after an ambiguous
// register() failure must resend the first attempt's EXACT cached material
// (including the recovery code) -- never regenerate it, even though
// generateSignupMaterial is deterministic in neither its salts/nonces/
// keypairs nor its recovery code. Regenerating on a resume is unsafe: if
// the first attempt's register() actually committed, internal/db/
// register.go's own #124 fix returns success without writing anything, so
// a resend with fresh material would show the user a recovery code that
// doesn't match what the server actually has stored. A resubmission with a
// DIFFERENT password must not resume either -- see the "changed password"
// test below -- since resending old material under a new password the user
// typed would make the post-register login unable to ever succeed.
//
// isDefinitelyUncommitted is table-tested directly against real ApiError
// instances, the same way PR #129 round 3 established for runRecovery's/
// runChangePassword's own copies, so the actual status-code boundary is
// pinned rather than exercised only through a stub.

import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import {
  isDefinitelyUncommitted,
  runSignup,
  signupErrorMessage,
  type PendingSignup,
  type SignupDeps,
  type SignupResult,
} from './runSignup'

const MATERIAL = {
  signingPublicKey: 'c2lnbmluZw==',
  wrappingPublicKey: 'd3JhcHBpbmc=',
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
  recoverySalt: 'cmVjb3Zlcnktc2FsdA==',
  recoveryArgon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryWrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'cmVjb3ZlcnktY2lwaGVy' },
  recoveryVerifierSalt: 'dmVyaWZpZXItc2FsdA==',
  recoveryVerifierParams: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  recoveryVerifier: 'dmVyaWZpZXI=',
  recoveryCode: 'NEW00-00000-00000-00000-000000',
}

// A second, distinctly different material -- standing in for what a second
// generateSignupMaterial call would produce (a different recovery code,
// different salts/nonces/keys), the way the real, non-deterministic
// implementation actually behaves. Used to prove a resumed attempt sends
// the FIRST material, never something that looks like this.
const REGENERATED_MATERIAL = {
  ...MATERIAL,
  wrappedPrivateKeys: { nonce: 'c2Vjb25kLW5vbmNl', ciphertext: 'c2Vjb25kLWNpcGhlcnRleHQ=' },
  recoveryVerifier: 'c2Vjb25kLXZlcmlmaWVy',
  recoveryCode: 'DIFF00-00000-00000-00000-000000',
}

const CHALLENGE_RESPONSE = {
  nonce: 'bm9uY2U=',
  userId: 'user-1',
  salt: 'c2FsdA==',
  argon2Params: { memoryKiB: 1, iterations: 1, parallelism: 1 },
  wrappedPrivateKeys: { nonce: 'bm9uY2U=', ciphertext: 'Y2lwaGVy' },
}

function makeDeps(overrides: Partial<SignupDeps> = {}): SignupDeps {
  return {
    generateUserID: vi.fn().mockReturnValue('generated-user-id'),
    generateSignupMaterial: vi.fn().mockResolvedValue(MATERIAL),
    register: vi.fn().mockResolvedValue({ userId: 'user-1' }),
    challenge: vi.fn().mockResolvedValue(CHALLENGE_RESPONSE),
    completeLogin: vi.fn().mockResolvedValue('signature'),
    verify: vi.fn().mockResolvedValue({ userId: 'user-1', credentialVersion: 1 }),
    onProgress: () => {},
    onLogin: () => {},
    onRegistered: () => {},
    ...overrides,
  }
}

function makeResume(overrides: Partial<PendingSignup> = {}): PendingSignup {
  return {
    username: 'alice',
    userId: 'first-attempt-user-id',
    password: 'password123',
    material: MATERIAL,
    ...overrides,
  }
}

describe('isDefinitelyUncommitted', () => {
  const cases: { readonly err: unknown; readonly uncommitted: boolean }[] = [
    { err: new ApiError(400, 'bad request'), uncommitted: true },
    { err: new ApiError(403, 'registration is closed'), uncommitted: true },
    { err: new ApiError(409, 'username is taken'), uncommitted: true },
    { err: new ApiError(409, 'userId is taken'), uncommitted: true },
    { err: new ApiError(500, 'internal'), uncommitted: false },
    { err: new ApiError(503, 'unavailable'), uncommitted: false },
    { err: new TypeError('Failed to fetch'), uncommitted: false },
    { err: new Error('plain error'), uncommitted: false },
  ]
  it.each(cases)(
    '$err.constructor.name $err.message -> uncommitted=$uncommitted',
    ({ err, uncommitted }) => {
      expect(isDefinitelyUncommitted(err)).toBe(uncommitted)
    },
  )
})

describe('runSignup (no resume / fresh attempt)', () => {
  it('generates a fresh userId and material on a plain (non-retry) submission', async () => {
    const deps = makeDeps()
    await runSignup(deps, 'alice', 'password123')

    expect(deps.generateUserID).toHaveBeenCalledOnce()
    expect(deps.generateSignupMaterial).toHaveBeenCalledWith(
      'password123',
      'generated-user-id',
      deps.onProgress,
    )
    expect(deps.register).toHaveBeenCalledWith(
      expect.objectContaining({ username: 'alice', userId: 'generated-user-id' }),
    )
  })

  it('returns ok:true with the material and loggedIn:true on full success', async () => {
    const onRegistered = vi.fn()
    const deps = makeDeps({ onRegistered })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result).toEqual({ ok: true, material: MATERIAL, loggedIn: true })
    expect(onRegistered).toHaveBeenCalledWith(MATERIAL)
  })

  it("calls onLogin with verify()'s userId only once login succeeds", async () => {
    const onLogin = vi.fn()
    const deps = makeDeps({ onLogin })
    await runSignup(deps, 'alice', 'password123')

    expect(onLogin).toHaveBeenCalledWith('user-1')
  })

  it('reports ok:true with loggedIn:false if the post-register login fails, without discarding material', async () => {
    const onLogin = vi.fn()
    const deps = makeDeps({
      challenge: vi.fn().mockRejectedValue(new Error('network error')),
      onLogin,
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result).toEqual({ ok: true, material: MATERIAL, loggedIn: false })
    expect(onLogin).not.toHaveBeenCalled()
  })

  it('a definite 4xx register() failure reports no resume -- nothing to retry', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(409, 'username is taken')),
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('definitelyUncommitted')
    expect(result.resume).toBeUndefined()
  })

  it('a generateSignupMaterial failure (e.g. a worker OOM) reports no resume -- nothing was ever sent', async () => {
    const deps = makeDeps({
      generateSignupMaterial: vi.fn().mockRejectedValue(new Error('worker: out of memory')),
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('definitelyUncommitted')
    expect(result.resume).toBeUndefined()
    expect(deps.register).not.toHaveBeenCalled()
  })

  it("an ambiguous register() failure (network error) returns a resume caching this attempt's userId AND material", async () => {
    const deps = makeDeps({
      generateUserID: vi.fn().mockReturnValue('first-attempt-user-id'),
      register: vi.fn().mockRejectedValue(new TypeError('Failed to fetch')),
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('ambiguous')
    expect(result.resume).toEqual({
      username: 'alice',
      userId: 'first-attempt-user-id',
      password: 'password123',
      material: MATERIAL,
    })
  })

  it('an ambiguous register() failure (5xx) also returns a resume', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(500, 'internal')),
    })
    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('ambiguous')
  })
})

describe('runSignup (resume)', () => {
  // This is PR #133 round 1's actual fix, exercised end to end at this
  // layer: a resubmission passing the prior ambiguous failure's exact
  // `resume` must NOT call generateUserID or generateSignupMaterial again,
  // and must send register() the EXACT cached material -- including the
  // recovery-code-derived recoveryVerifier -- not a freshly generated one
  // that merely happens to share a userId.
  it('a matching resume reuses the cached userId and material verbatim, never regenerating', async () => {
    const deps = makeDeps({
      generateUserID: vi.fn().mockReturnValue('should-not-be-used'),
      generateSignupMaterial: vi.fn().mockResolvedValue(REGENERATED_MATERIAL),
    })
    const resume = makeResume()

    const result = await runSignup(deps, 'alice', 'password123', resume)

    expect(deps.generateUserID).not.toHaveBeenCalled()
    expect(deps.generateSignupMaterial).not.toHaveBeenCalled()
    expect(deps.register).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'first-attempt-user-id',
        signingPublicKey: MATERIAL.signingPublicKey,
        wrappingPublicKey: MATERIAL.wrappingPublicKey,
        salt: MATERIAL.salt,
        wrappedPrivateKeys: MATERIAL.wrappedPrivateKeys,
        recoverySalt: MATERIAL.recoverySalt,
        recoveryWrappedPrivateKeys: MATERIAL.recoveryWrappedPrivateKeys,
        recoveryVerifierSalt: MATERIAL.recoveryVerifierSalt,
        recoveryVerifier: MATERIAL.recoveryVerifier,
      }),
    )
    // The register() call must not contain anything from
    // REGENERATED_MATERIAL -- proves generateSignupMaterial's mock return
    // value truly went unused, not just uncalled.
    const sent = (deps.register as ReturnType<typeof vi.fn>).mock.calls[0]?.[0] as {
      recoveryVerifier: string
    }
    expect(sent.recoveryVerifier).not.toBe(REGENERATED_MATERIAL.recoveryVerifier)
    if (result.ok) {
      expect(result.material).toEqual(MATERIAL)
    } else {
      throw new Error('expected ok:true')
    }
  })

  it('a resume whose password no longer matches is ignored -- runs a genuinely fresh attempt instead', async () => {
    const deps = makeDeps({
      generateUserID: vi.fn().mockReturnValue('fresh-user-id'),
      generateSignupMaterial: vi.fn().mockResolvedValue(REGENERATED_MATERIAL),
    })
    // The user fixed a typo: same username, but a DIFFERENT password than
    // the one the cached resume was generated under.
    const resume = makeResume({ password: 'the-old-typo-password' })

    const result = await runSignup(deps, 'alice', 'a-corrected-password', resume)

    expect(deps.generateUserID).toHaveBeenCalledOnce()
    expect(deps.generateSignupMaterial).toHaveBeenCalledWith(
      'a-corrected-password',
      'fresh-user-id',
      deps.onProgress,
    )
    expect(deps.register).toHaveBeenCalledWith(
      expect.objectContaining({
        userId: 'fresh-user-id',
        recoveryVerifier: REGENERATED_MATERIAL.recoveryVerifier,
      }),
    )
    if (result.ok) {
      expect(result.material).toEqual(REGENERATED_MATERIAL)
    } else {
      throw new Error('expected ok:true')
    }
  })

  it('a resume for a different username is ignored -- runs a genuinely fresh attempt instead', async () => {
    const deps = makeDeps({
      generateUserID: vi.fn().mockReturnValue('fresh-user-id'),
    })
    const resume = makeResume({ username: 'alice' })

    await runSignup(deps, 'someone-else', 'password123', resume)

    expect(deps.generateUserID).toHaveBeenCalledOnce()
    expect(deps.generateSignupMaterial).toHaveBeenCalledWith(
      'password123',
      'fresh-user-id',
      deps.onProgress,
    )
    expect(deps.register).toHaveBeenCalledWith(
      expect.objectContaining({ username: 'someone-else', userId: 'fresh-user-id' }),
    )
  })

  it('a successful resumed retry surfaces the SAME recovery code the first attempt cached, not a new one', async () => {
    const deps = makeDeps({
      generateSignupMaterial: vi.fn().mockResolvedValue(REGENERATED_MATERIAL),
    })
    const resume = makeResume()

    const result = await runSignup(deps, 'alice', 'password123', resume)

    if (!result.ok) {
      throw new Error('expected ok:true')
    }
    // This is the actual user-facing consequence of round 1's bug: showing
    // REGENERATED_MATERIAL.recoveryCode here would be a recovery code the
    // server never actually stored, since its own #124 fix wrote nothing
    // on a matching retry.
    expect(result.material.recoveryCode).toBe(MATERIAL.recoveryCode)
  })
})

// Issue #134: the scenario is a resubmission with a DIFFERENT password
// (so runSignup's own resuming check above correctly declines to reuse
// `resume`'s material) whose fresh register() call then collides with the
// account the FIRST attempt actually created. Without this, the caller has
// no way to tell that apart from a genuine "someone else has this name"
// conflict and discards the only path back to the first attempt's recovery
// code -- see this file's own header, runSignup.ts's doc comment on the
// 'definitelyUncommitted' branch, and SignupScreen.tsx's handling of
// result.resume.
describe('runSignup (issue #134: username_taken after a password change)', () => {
  it('a username_taken 409 matching a stale resume echoes that SAME resume back, not the fresh attempt', async () => {
    const deps = makeDeps({
      generateUserID: vi.fn().mockReturnValue('fresh-user-id'),
      generateSignupMaterial: vi.fn().mockResolvedValue(REGENERATED_MATERIAL),
      register: vi.fn().mockRejectedValue(new ApiError(409, 'username is taken', 'username_taken')),
    })
    const resume = makeResume()

    // Same username as `resume`, but a different (corrected) password -- so
    // resuming is declined and a genuinely fresh attempt runs, which then
    // hits the real conflict left by the first, already-committed attempt.
    const result = await runSignup(deps, 'alice', 'a-different-password', resume)

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('definitelyUncommitted')
    // Echoes the ORIGINAL resume verbatim -- NOT a resume built from this
    // failed attempt's own (fresh, never-committed) material, which would
    // silently point the user at a recovery code the server never stored.
    expect(result.resume).toEqual(resume)
    expect(result.resume?.material).toBe(MATERIAL)
  })

  // Round 1 review's blocking finding: a username_taken 409 on the EXACT
  // resend (same username AND password as `resume`) means the opposite of
  // the case above. If the resend's userId and material had actually
  // matched what committed, the server's own #124 fix (isOwnRegistration,
  // internal/db/register.go) would return 201, not 409 -- so a 409 here
  // proves the original attempt did NOT land under this username (its
  // claim never committed, or someone else took the name since). Echoing
  // `resume` back in this case would tell the user to keep resubmitting
  // the exact password that keeps failing, with no way out short of
  // changing the username or reloading -- reproduced live against this
  // branch pre-fix by the reviewer (three identical resubmissions, same
  // "try your original password" response every time).
  it('a username_taken 409 on the EXACT resend (same username AND password) reports no resume', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(409, 'username is taken', 'username_taken')),
    })
    const resume = makeResume()

    const result = await runSignup(deps, resume.username, resume.password, resume)

    expect(deps.generateUserID).not.toHaveBeenCalled()
    expect(deps.generateSignupMaterial).not.toHaveBeenCalled()
    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('definitelyUncommitted')
    expect(result.resume).toBeUndefined()
  })

  it('a username_taken 409 with NO stale resume reports no resume -- an ordinary conflict', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(409, 'username is taken', 'username_taken')),
    })

    const result = await runSignup(deps, 'alice', 'password123')

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.kind).toBe('definitelyUncommitted')
    expect(result.resume).toBeUndefined()
  })

  it('a username_taken 409 whose resume is for a DIFFERENT username reports no resume', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(409, 'username is taken', 'username_taken')),
    })
    // A stale resume exists, but from an entirely different signup attempt
    // -- SignupScreen only ever hands runSignup a resume whose username
    // already matches (see its own header comment), but runSignup's own
    // check must not assume that invariant blindly.
    const resume = makeResume({ username: 'someone-else' })

    const result = await runSignup(deps, 'alice', 'password123', resume)

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.resume).toBeUndefined()
  })

  it('a username_taken 409 without the machine-readable code reports no resume', async () => {
    // Defensive: only WriteErrorWithCode's specific username_taken code
    // triggers this, never a message-string match alone -- guards against a
    // server-side wording change silently breaking (or, worse, silently
    // mis-triggering) this path.
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(409, 'username is taken')),
    })
    const resume = makeResume()

    const result = await runSignup(deps, 'alice', 'a-different-password', resume)

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.resume).toBeUndefined()
  })

  it('a DIFFERENT 409 (user_id_taken) matching a stale resume still reports no resume -- only username_taken qualifies', async () => {
    const deps = makeDeps({
      register: vi.fn().mockRejectedValue(new ApiError(409, 'userId is taken', 'user_id_taken')),
    })
    const resume = makeResume()

    const result = await runSignup(deps, 'alice', 'a-different-password', resume)

    expect(result.ok).toBe(false)
    if (result.ok) {
      throw new Error('unreachable')
    }
    expect(result.resume).toBeUndefined()
  })
})

// signupErrorMessage is what SignupScreen.tsx actually shows -- see its own
// doc comment. The 'ambiguous'-also-has-a-resume case here is a regression
// guard specifically: an earlier draft of #134's fix keyed the hint message
// off `result.resume !== undefined` alone, which also (wrongly) fires for
// the ordinary #124/#133 ambiguous-retry-caching case, since THAT kind of
// result carries a resume too. Caught by hand during review, not by a
// test, before this was added -- SignupScreen.tsx has no component test
// covering this, hence testing the pure function directly.
describe('signupErrorMessage', () => {
  const definitelyUncommittedNoResume: Extract<SignupResult, { ok: false }> = {
    ok: false,
    kind: 'definitelyUncommitted',
    error: new ApiError(409, 'username is taken', 'username_taken'),
  }

  it('shows the #134 hint for a definitelyUncommitted result WITH a resume', () => {
    const result: Extract<SignupResult, { ok: false }> = {
      ...definitelyUncommittedNoResume,
      resume: makeResume(),
    }
    expect(signupErrorMessage(result)).toBe(
      'An earlier attempt may have already created this account. Resubmit with your original password to see its recovery code, or log in and use Change password to get a new one.',
    )
  })

  it('shows the server message for a definitelyUncommitted result with NO resume', () => {
    expect(signupErrorMessage(definitelyUncommittedNoResume)).toBe('username is taken')
  })

  it('does NOT show the #134 hint for an ambiguous result, even though it also carries a resume', () => {
    const result: Extract<SignupResult, { ok: false }> = {
      ok: false,
      kind: 'ambiguous',
      error: new TypeError('Failed to fetch'),
      resume: makeResume(),
    }
    expect(signupErrorMessage(result)).not.toContain('earlier attempt')
    expect(signupErrorMessage(result)).toBe('Could not create your account. Try again.')
  })

  it('shows the generic message, not the server 403 message, for a closed-registration failure', () => {
    const result: Extract<SignupResult, { ok: false }> = {
      ok: false,
      kind: 'definitelyUncommitted',
      error: new ApiError(403, 'registration is closed'),
    }
    expect(signupErrorMessage(result)).toBe('Could not create your account. Try again.')
  })

  it('shows the generic message for a non-ApiError (e.g. a worker OOM)', () => {
    const result: Extract<SignupResult, { ok: false }> = {
      ok: false,
      kind: 'definitelyUncommitted',
      error: new Error('worker: out of memory'),
    }
    expect(signupErrorMessage(result)).toBe('Could not create your account. Try again.')
  })
})
