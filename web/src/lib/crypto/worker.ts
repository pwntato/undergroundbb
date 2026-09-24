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
} from './credential-material.js'
import type {
  ChangePasswordMaterial,
  CompleteChangePasswordRequest,
  CompleteLoginRequest,
  CompleteRecoveryRequest,
  GenerateSignupMaterialRequest,
  RecoveryMaterial,
  SignupMaterial,
  WorkerRequest,
  WorkerResponse,
} from './worker-protocol.js'

const ctx = self as unknown as DedicatedWorkerGlobalScope

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
  const signature = await completeLoginPure(req)
  post({ kind: 'completeLoginDone', id: req.id, signature })
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
