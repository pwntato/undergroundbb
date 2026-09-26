// The crypto worker: every Argon2id derivation, keypair generation, wrap and
// signature this app performs runs here, off the main thread, per
// docs/DESIGN.md's "Frontend" section ("Argon2id runs in WebAssembly, and
// all crypto runs in a Web Worker so decrypting a page of posts does not
// block the UI"). The password itself is only ever posted into this worker
// and never returns from it -- only public material, wire-ready wrapped
// blobs, and a signature cross back.
//
// This file is a thin adapter over credential-material.ts's pure functions:
// it owns the postMessage boundary (parsing a request, calling the matching
// pure function, posting its progress events and result back) and nothing
// else. The pure logic lives in credential-material.ts specifically so it
// can be unit-tested directly -- this file's own top-level `self as
// DedicatedWorkerGlobalScope` throws outside a real worker/browser context,
// so nothing in this file itself can ever be imported by a test (PR #129
// review, after `wrapNewCredentials` moved but this file did not).

/// <reference lib="webworker" />

import {
  completeChangePassword as completeChangePasswordPure,
  completeLogin as completeLoginPure,
  completeRecovery as completeRecoveryPure,
  generateSignupMaterial as generateSignupMaterialPure,
  signGroupCreation as signGroupCreationPure,
  type LiveKeys,
} from './credential-material.js'
import { base64ToBytes } from './base64.js'
import type {
  ChangePasswordMaterial,
  ClearLiveKeysRequest,
  CompleteChangePasswordRequest,
  CompleteLoginRequest,
  CompleteRecoveryRequest,
  GenerateSignupMaterialRequest,
  RecoveryMaterial,
  SignGroupCreationRequest,
  SignupMaterial,
  WorkerRequest,
  WorkerResponse,
} from './worker-protocol.js'

const ctx = self as unknown as DedicatedWorkerGlobalScope

/**
 * The current tab's unwrapped keypair, live only inside this worker instance
 * -- issue #34. Populated as a side effect of a successful completeLogin
 * (which itself only posts back a signature, unchanged from before this
 * cache existed -- see credential-material.ts's completeLogin doc comment),
 * and read by signGroupCreation. Cleared on clearLiveKeys (posted on
 * logout) so a worker instance reused across a logout/login in the same tab
 * never signs under a previous account's keys.
 *
 * This is the ONLY place a live private key exists outside a function's own
 * call stack in this entire app -- it never crosses postMessage in either
 * direction, matching this file's own module doc comment ("only public
 * material, wire-ready wrapped blobs, and a signature cross back"). A main
 * thread compromised by a malicious dependency can ask this worker to sign
 * things, but cannot read the key itself out of it.
 */
let liveKeys: LiveKeys | null = null

ctx.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const req = event.data
  void handle(req).catch((err: unknown) => {
    post({
      kind: 'error',
      id: req.id,
      message: err instanceof Error ? err.message : String(err),
      errorName: err instanceof Error ? err.name : 'Error',
    })
  })
}

async function handle(req: WorkerRequest): Promise<void> {
  switch (req.kind) {
    case 'generateSignupMaterial':
      await generateSignupMaterial(req)
      return
    case 'completeLogin':
      await completeLogin(req)
      return
    case 'completeRecovery':
      await completeRecovery(req)
      return
    case 'completeChangePassword':
      await completeChangePassword(req)
      return
    case 'signGroupCreation':
      await signGroupCreation(req)
      return
    case 'clearLiveKeys':
      clearLiveKeys(req)
      return
  }
}

function post(msg: WorkerResponse): void {
  ctx.postMessage(msg)
}

async function generateSignupMaterial(req: GenerateSignupMaterialRequest): Promise<void> {
  const result: SignupMaterial = await generateSignupMaterialPure(req.userId, req.password, (p) => {
    post({ kind: 'signupProgress', id: req.id, ...p })
  })
  post({ kind: 'generateSignupMaterialDone', id: req.id, result })
}

async function completeLogin(req: CompleteLoginRequest): Promise<void> {
  const { signature, keys } = await completeLoginPure(req)
  // Cached AFTER a successful unwrap+sign -- a failed completeLoginPure call
  // (wrong password) throws before reaching here, via handle()'s own
  // try/catch (this file's top-level onmessage), so liveKeys is never
  // populated from a login attempt that didn't actually prove the password.
  liveKeys = keys
  post({ kind: 'completeLoginDone', id: req.id, signature })
}

/**
 * Signs a new group's trust anchor and root role grant, and wraps its
 * generation-0 key to the caller's own wrapping public key, using liveKeys
 * -- issue #34. Throws if liveKeys is unset (no completeLogin has succeeded
 * in this worker instance's lifetime -- e.g. the tab was reloaded since
 * login, which resets this module's state along with everything else) or
 * belongs to a different account than req.userId claims, so a caller
 * cannot accidentally sign as whichever account happened to log in most
 * recently in a worker instance reused across a logout/login in the same
 * tab.
 */
async function signGroupCreation(req: SignGroupCreationRequest): Promise<void> {
  if (liveKeys === null) {
    throw new Error(
      'worker: no live keys cached -- log in again before creating a group (this can happen after a page reload)',
    )
  }
  if (liveKeys.userId !== req.userId) {
    throw new Error('worker: cached keys belong to a different account than requested')
  }
  const result = await signGroupCreationPure(liveKeys, req.groupId, base64ToBytes(req.groupKey))
  post({ kind: 'signGroupCreationDone', id: req.id, result })
}

function clearLiveKeys(_req: ClearLiveKeysRequest): void {
  liveKeys = null
}

async function completeRecovery(req: CompleteRecoveryRequest): Promise<void> {
  const wrapped = await completeRecoveryPure(req, (p) => {
    post({ kind: 'signupProgress', id: req.id, ...p })
  })
  const result: RecoveryMaterial = wrapped
  post({ kind: 'completeRecoveryDone', id: req.id, result })
}

async function completeChangePassword(req: CompleteChangePasswordRequest): Promise<void> {
  const wrapped = await completeChangePasswordPure(req, (p) => {
    post({ kind: 'signupProgress', id: req.id, ...p })
  })
  const result: ChangePasswordMaterial = wrapped
  post({ kind: 'completeChangePasswordDone', id: req.id, result })
}
