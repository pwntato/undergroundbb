// Main-thread wrapper around worker.ts -- the only place in the app that
// talks to the crypto worker directly. Callers get a promise per request;
// generateSignupMaterial also takes an onProgress callback for #33's
// "honest progress" requirement (worker.ts's signupProgress events).
//
// One worker instance is created lazily and reused for the page's lifetime:
// spinning up hash-wasm's Argon2id module has real cost, and nothing about
// this app needs more than one crypto call in flight at a time.

import type {
  CompleteLoginRequest,
  CompleteLoginResponse,
  GenerateSignupMaterialRequest,
  GenerateSignupMaterialResponse,
  SignupMaterial,
  SignupProgressEvent,
  WorkerResponse,
} from './worker-protocol.js'

let worker: Worker | undefined

function getWorker(): Worker {
  worker ??= new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
  return worker
}

function nextRequestID(): string {
  return crypto.randomUUID()
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
    const onMessage = (event: MessageEvent<WorkerResponse>): void => {
      const msg = event.data
      if (msg.id !== id) {
        return
      }
      if (msg.kind === 'signupProgress') {
        onProgress(msg)
        return
      }
      w.removeEventListener('message', onMessage)
      if (msg.kind === 'error') {
        reject(new Error(msg.message))
        return
      }
      if (msg.kind === 'generateSignupMaterialDone') {
        resolve((msg as GenerateSignupMaterialResponse).result)
        return
      }
      reject(new Error(`worker: unexpected response kind ${msg.kind} for generateSignupMaterial`))
    }
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
    const onMessage = (event: MessageEvent<WorkerResponse>): void => {
      const msg = event.data
      if (msg.id !== id) {
        return
      }
      w.removeEventListener('message', onMessage)
      if (msg.kind === 'error') {
        reject(new Error(msg.message))
        return
      }
      if (msg.kind === 'completeLoginDone') {
        resolve((msg as CompleteLoginResponse).signature)
        return
      }
      reject(new Error(`worker: unexpected response kind ${msg.kind} for completeLogin`))
    }
    w.addEventListener('message', onMessage)
    w.postMessage(fullReq)
  })
}
