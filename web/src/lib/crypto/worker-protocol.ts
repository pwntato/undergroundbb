// Message shapes shared between the crypto worker (worker.ts, running off
// the main thread per docs/DESIGN.md's "Frontend" section) and its client
// wrapper (worker-client.ts). Kept in its own module, with no worker-only or
// DOM-only imports, so the main thread can import these types without
// pulling in anything that only makes sense inside a worker.
//
// Every request carries an explicit id so the client can correlate a
// response (or a progress event) to the call that started it -- necessary
// because a single worker instance may have more than one call in flight
// conceptually (signup's three sequential derivations all go through the
// same worker), even though this module always awaits one at a time today.

export interface GenerateSignupMaterialRequest {
  readonly kind: 'generateSignupMaterial'
  readonly id: string
  readonly password: string
}

/**
 * One step of signup's three independent Argon2id derivations, reported as
 * it completes -- see recovery-code.ts's neighbor, argon2.ts, and #33's own
 * requirement for "honest progress": each step fires only once that step's
 * derivation has actually finished, never on a timer.
 */
export interface SignupProgressEvent {
  readonly kind: 'signupProgress'
  readonly id: string
  readonly step: 1 | 2 | 3
  readonly totalSteps: 3
  readonly label: string
}

export interface SignupMaterial {
  readonly signingPublicKey: string
  readonly wrappingPublicKey: string

  readonly salt: string
  readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
  readonly wrappedPrivateKeys: { nonce: string; ciphertext: string }

  readonly recoverySalt: string
  readonly recoveryArgon2Params: { memoryKiB: number; iterations: number; parallelism: number }
  readonly recoveryWrappedPrivateKeys: { nonce: string; ciphertext: string }

  readonly recoveryVerifierSalt: string
  readonly recoveryVerifierParams: { memoryKiB: number; iterations: number; parallelism: number }
  readonly recoveryVerifier: string

  /** Shown to the user once, on the recovery-code screen. Never sent to the server. */
  readonly recoveryCode: string
}

export interface GenerateSignupMaterialResponse {
  readonly kind: 'generateSignupMaterialDone'
  readonly id: string
  readonly result: SignupMaterial
}

export interface CompleteLoginRequest {
  readonly kind: 'completeLogin'
  readonly id: string
  readonly password: string
  readonly salt: string
  readonly argon2Params: { memoryKiB: number; iterations: number; parallelism: number }
  readonly wrappedPrivateKeys: { nonce: string; ciphertext: string }
  readonly userId: string
  readonly nonce: string
}

export interface CompleteLoginResponse {
  readonly kind: 'completeLoginDone'
  readonly id: string
  readonly signature: string
}

export interface WorkerErrorResponse {
  readonly kind: 'error'
  readonly id: string
  readonly message: string
}

export type WorkerRequest = GenerateSignupMaterialRequest | CompleteLoginRequest

export type WorkerResponse =
  SignupProgressEvent | GenerateSignupMaterialResponse | CompleteLoginResponse | WorkerErrorResponse
