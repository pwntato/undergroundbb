// Main-thread wrapper around worker.ts -- the only place in the app that
// talks to the crypto worker directly. Callers get a promise per request;
// generateSignupMaterial also takes an onProgress callback for #33's
// "honest progress" requirement (worker.ts's signupProgress events).
//
// One worker instance is created lazily and reused for the page's lifetime:
// spinning up hash-wasm's Argon2id module has real cost, and nothing about
// this app needs more than one crypto call in flight at a time.

import { DecryptionFailedError } from './aesgcm.js'
import type {
  ChangePasswordMaterial,
  ClearLiveKeysRequest,
  CompleteChangePasswordRequest,
  CompleteChangePasswordResponse,
  CompleteLoginRequest,
  CompleteLoginResponse,
  CompleteRecoveryRequest,
  CompleteRecoveryResponse,
  GenerateSignupMaterialRequest,
  GenerateSignupMaterialResponse,
  RecoveryMaterial,
  SignGroupCreationRequest,
  SignGroupCreationResponse,
  SignGroupCreationResult,
  SignupMaterial,
  SignupProgressEvent,
  WorkerErrorResponse,
  WorkerResponse,
} from './worker-protocol.js'

/**
 * Reconstructs a typed error from a WorkerErrorResponse where possible.
 * worker.ts's top-level catch can only forward plain data across the
 * postMessage boundary -- the original error's class is lost -- so this is
 * how a caller (LoginScreen, distinguishing "wrong password" from every
 * other login failure) gets a real DecryptionFailedError back rather than
 * having to string-match msg.message against aesgcm.ts's literal text.
 * Every other error name falls back to a plain Error carrying the message.
 */
function reconstructWorkerError(msg: WorkerErrorResponse): Error {
  if (msg.errorName === 'DecryptionFailedError') {
    return new DecryptionFailedError()
  }
  return new Error(msg.message)
}

let worker: Worker | undefined

function getWorker(): Worker {
  worker ??= new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
  return worker
}

function nextRequestID(): string {
  return crypto.randomUUID()
}

/**
 * Attaches the 'error'/'messageerror' listeners a request/response round
 * trip needs beyond its own {kind:'error'} message handling: if the worker
 * module itself fails to load, or something throws outside worker.ts's own
 * handle() (e.g. a large Argon2id allocation failing on a low-memory mobile
 * tab), no {kind:'error'} response ever arrives and the caller's promise
 * would otherwise never settle -- leaving the UI (e.g. SignupProgressStep)
 * stuck with no way out but a reload. Either failure discards the cached
 * worker so the next call gets a fresh instance rather than reusing one
 * that may be in a broken state. Returns a cleanup function the caller must
 * also invoke once its own message handler settles the promise normally.
 */
function attachFailureHandlers(
  w: Worker,
  onMessage: (event: MessageEvent<WorkerResponse>) => void,
  reject: (err: Error) => void,
): () => void {
  const onError = (event: ErrorEvent): void => {
    cleanup()
    w.terminate()
    worker = undefined
    reject(new Error(`worker: ${event.message || 'failed to load or threw outside handle()'}`))
  }
  const onMessageError = (): void => {
    cleanup()
    w.terminate()
    worker = undefined
    reject(new Error('worker: received an unstructured-cloneable-violating message'))
  }
  const cleanup = (): void => {
    w.removeEventListener('message', onMessage)
    w.removeEventListener('error', onError)
    w.removeEventListener('messageerror', onMessageError)
  }
  w.addEventListener('error', onError)
  w.addEventListener('messageerror', onMessageError)
  return cleanup
}

/** Runs generateSignupMaterial in the crypto worker, reporting each step via onProgress as it completes. */
export function generateSignupMaterial(
  password: string,
  userId: string,
  onProgress: (event: SignupProgressEvent) => void,
): Promise<SignupMaterial> {
  const id = nextRequestID()
  const req: GenerateSignupMaterialRequest = {
    kind: 'generateSignupMaterial',
    id,
    password,
    userId,
  }
  return new Promise((resolve, reject) => {
    const w = getWorker()
    let cleanup: () => void
    const onMessage = (event: MessageEvent<WorkerResponse>): void => {
      const msg = event.data
      if (msg.id !== id) {
        return
      }
      if (msg.kind === 'signupProgress') {
        onProgress(msg)
        return
      }
      cleanup()
      if (msg.kind === 'error') {
        reject(reconstructWorkerError(msg))
        return
      }
      if (msg.kind === 'generateSignupMaterialDone') {
        resolve((msg as GenerateSignupMaterialResponse).result)
        return
      }
      reject(new Error(`worker: unexpected response kind ${msg.kind} for generateSignupMaterial`))
    }
    cleanup = attachFailureHandlers(w, onMessage, reject)
    w.addEventListener('message', onMessage)
    w.postMessage(req)
  })
}

/** Runs completeLogin in the crypto worker, returning the Ed25519 signature over the challenge nonce. */
export function completeLogin(req: Omit<CompleteLoginRequest, 'kind' | 'id'>): Promise<string> {
  const id = nextRequestID()
  const fullReq: CompleteLoginRequest = { kind: 'completeLogin', id, ...req }
  return new Promise((resolve, reject) => {
    const w = getWorker()
    let cleanup: () => void
    const onMessage = (event: MessageEvent<WorkerResponse>): void => {
      const msg = event.data
      if (msg.id !== id) {
        return
      }
      cleanup()
      if (msg.kind === 'error') {
        reject(reconstructWorkerError(msg))
        return
      }
      if (msg.kind === 'completeLoginDone') {
        resolve((msg as CompleteLoginResponse).signature)
        return
      }
      reject(new Error(`worker: unexpected response kind ${msg.kind} for completeLogin`))
    }
    cleanup = attachFailureHandlers(w, onMessage, reject)
    w.addEventListener('message', onMessage)
    w.postMessage(fullReq)
  })
}

/**
 * Runs completeRecovery in the crypto worker: redeems a recovery code and
 * issues a brand-new full credential set under a new password, reporting
 * each step via onProgress as it completes (same "honest progress"
 * requirement generateSignupMaterial's caller relies on). A wrong username
 * or recovery code fails inside the worker's unwrap as a
 * DecryptionFailedError, the same signal completeLogin gives for a wrong
 * password -- see aesgcm.ts.
 */
export function completeRecovery(
  req: Omit<CompleteRecoveryRequest, 'kind' | 'id'>,
  onProgress: (event: SignupProgressEvent) => void,
): Promise<RecoveryMaterial> {
  const id = nextRequestID()
  const fullReq: CompleteRecoveryRequest = { kind: 'completeRecovery', id, ...req }
  return new Promise((resolve, reject) => {
    const w = getWorker()
    let cleanup: () => void
    const onMessage = (event: MessageEvent<WorkerResponse>): void => {
      const msg = event.data
      if (msg.id !== id) {
        return
      }
      if (msg.kind === 'signupProgress') {
        onProgress(msg)
        return
      }
      cleanup()
      if (msg.kind === 'error') {
        reject(reconstructWorkerError(msg))
        return
      }
      if (msg.kind === 'completeRecoveryDone') {
        resolve((msg as CompleteRecoveryResponse).result)
        return
      }
      reject(new Error(`worker: unexpected response kind ${msg.kind} for completeRecovery`))
    }
    cleanup = attachFailureHandlers(w, onMessage, reject)
    w.addEventListener('message', onMessage)
    w.postMessage(fullReq)
  })
}

/**
 * Runs completeChangePassword in the crypto worker: unwraps the caller's
 * PROFILE copy with their old password and re-wraps it under a new
 * password plus a freshly issued recovery code, reporting each step via
 * onProgress as it completes (same "honest progress" requirement
 * generateSignupMaterial/completeRecovery's callers rely on). A wrong old
 * password fails inside the worker's unwrap as a DecryptionFailedError, the
 * same signal completeLogin gives for a wrong password.
 */
export function completeChangePassword(
  req: Omit<CompleteChangePasswordRequest, 'kind' | 'id'>,
  onProgress: (event: SignupProgressEvent) => void,
): Promise<ChangePasswordMaterial> {
  const id = nextRequestID()
  const fullReq: CompleteChangePasswordRequest = { kind: 'completeChangePassword', id, ...req }
  return new Promise((resolve, reject) => {
    const w = getWorker()
    let cleanup: () => void
    const onMessage = (event: MessageEvent<WorkerResponse>): void => {
      const msg = event.data
      if (msg.id !== id) {
        return
      }
      if (msg.kind === 'signupProgress') {
        onProgress(msg)
        return
      }
      cleanup()
      if (msg.kind === 'error') {
        reject(reconstructWorkerError(msg))
        return
      }
      if (msg.kind === 'completeChangePasswordDone') {
        resolve((msg as CompleteChangePasswordResponse).result)
        return
      }
      reject(new Error(`worker: unexpected response kind ${msg.kind} for completeChangePassword`))
    }
    cleanup = attachFailureHandlers(w, onMessage, reject)
    w.addEventListener('message', onMessage)
    w.postMessage(fullReq)
  })
}

/**
 * Signs a new group's trust anchor and root role grant, and wraps its
 * generation-0 key to the caller's own wrapping public key -- issue #34.
 * Relies entirely on the worker's own cached liveKeys (populated by an
 * earlier completeLogin call in this same worker instance); there is no
 * password or private key parameter here, unlike every other function in
 * this file, because the whole point of caching keys inside the worker is
 * that the main thread never holds one to pass. Rejects if no completeLogin
 * has succeeded in this worker instance's lifetime (e.g. the page was
 * reloaded since login) -- see worker.ts's own signGroupCreation for the
 * exact error.
 */
export function signGroupCreation(
  req: Omit<SignGroupCreationRequest, 'kind' | 'id'>,
): Promise<SignGroupCreationResult> {
  const id = nextRequestID()
  const fullReq: SignGroupCreationRequest = { kind: 'signGroupCreation', id, ...req }
  return new Promise((resolve, reject) => {
    const w = getWorker()
    let cleanup: () => void
    const onMessage = (event: MessageEvent<WorkerResponse>): void => {
      const msg = event.data
      if (msg.id !== id) {
        return
      }
      cleanup()
      if (msg.kind === 'error') {
        reject(reconstructWorkerError(msg))
        return
      }
      if (msg.kind === 'signGroupCreationDone') {
        resolve((msg as SignGroupCreationResponse).result)
        return
      }
      reject(new Error(`worker: unexpected response kind ${msg.kind} for signGroupCreation`))
    }
    cleanup = attachFailureHandlers(w, onMessage, reject)
    w.addEventListener('message', onMessage)
    w.postMessage(fullReq)
  })
}

/**
 * Clears the worker's cached liveKeys -- call on logout. Fire-and-forget:
 * there is no response to await, and no failure mode worth surfacing (worst
 * case, the worker is terminated and replaced before this message is even
 * processed, which clears the cache just as effectively).
 */
export function clearLiveKeys(): void {
  const req: ClearLiveKeysRequest = { kind: 'clearLiveKeys', id: nextRequestID() }
  getWorker().postMessage(req)
}
