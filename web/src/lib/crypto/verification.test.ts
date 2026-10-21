// Tests for evaluateVerification. Every record is signed with a real key
// through the same verificationPayload/sign the app uses, so a rejection is the
// evaluator's decision and not a malformed fixture. Each test names the rule it
// pins.

import { describe, expect, it } from 'vitest'
import { bytesToBase64 } from './base64.js'
import { SigningContext, generateSigningKey, sign, type SigningKey } from './ed25519.js'
import { fingerprint } from './fingerprint.js'
import {
  evaluateVerification,
  verificationPayload,
  type VerificationRecord,
} from './verification.js'

const ME = 'a0000000-0000-4000-8000-000000000001'
const BOB = 'b0000000-0000-4000-8000-000000000002'
const CAROL = 'c0000000-0000-4000-8000-000000000003'
const DAY = '2026-10-21'

const me = generateSigningKey()
const bob = generateSigningKey()
const wrapA = new Uint8Array(32).fill(7)
const wrapB = new Uint8Array(32).fill(9)
const bobFp = fingerprint(bob.publicKey, wrapA)

function makeRecord(
  opts: {
    signer?: SigningKey
    verifier?: string
    verified?: string
    fp?: string
    recordedVerified?: string
    recordedSigner?: SigningKey
    day?: string
    recordedDay?: string
  } = {},
): VerificationRecord {
  const signer = opts.signer ?? me
  const fp = opts.fp ?? bobFp
  const payload = verificationPayload(
    opts.verifier ?? ME,
    opts.verified ?? BOB,
    signer.publicKey,
    fp,
    opts.day ?? DAY,
  )
  return {
    verifiedUserId: opts.recordedVerified ?? opts.verified ?? BOB,
    fingerprint: fp,
    verifierSigningPublicKey: bytesToBase64((opts.recordedSigner ?? signer).publicKey),
    signature: bytesToBase64(sign(signer, SigningContext.Verification, payload)),
    signedDay: opts.recordedDay ?? opts.day ?? DAY,
  }
}

function evaluate(
  record: VerificationRecord | undefined,
  servedFingerprint: string | null = bobFp,
  verifiedUserId = BOB,
) {
  return evaluateVerification({
    verifierUserId: ME,
    verifierSigningPublicKey: me.publicKey,
    verifiedUserId,
    record,
    servedFingerprint,
  })
}

describe('evaluateVerification', () => {
  it('no record is none, the ordinary unverified case', () => {
    expect(evaluate(undefined)).toBe('none')
  })

  it('a valid record whose fingerprint equals the served one is verified', () => {
    expect(evaluate(makeRecord())).toBe('verified')
  })

  it('a valid record is changed when the served keys now give another fingerprint', () => {
    expect(evaluate(makeRecord(), fingerprint(bob.publicKey, wrapB))).toBe('changed')
    expect(evaluate(makeRecord(), fingerprint(generateSigningKey().publicKey, wrapA))).toBe(
      'changed',
    )
  })

  it('a valid record is changed, not verified, when the served fingerprint cannot be computed', () => {
    expect(evaluate(makeRecord(), null)).toBe('changed')
  })

  it('a record signed by another key is bad-signature, never none', () => {
    expect(evaluate(makeRecord({ signer: generateSigningKey() }))).toBe('bad-signature')
  })

  it('a record whose recorded signer is not my current key is bad-signature even if it verifies under that key', () => {
    const other = generateSigningKey()
    expect(evaluate(makeRecord({ signer: other }))).toBe('bad-signature')
  })

  it('a record claiming my key but signed by another is bad-signature', () => {
    expect(evaluate(makeRecord({ signer: generateSigningKey(), recordedSigner: me }))).toBe(
      'bad-signature',
    )
  })

  it('a record signed for another verified user is bad-signature', () => {
    expect(evaluate(makeRecord({ verified: CAROL, recordedVerified: BOB }))).toBe('bad-signature')
  })

  it('a record filed under another user is bad-signature', () => {
    expect(evaluate(makeRecord(), bobFp, CAROL)).toBe('bad-signature')
  })

  it('a record signed as someone else is bad-signature', () => {
    expect(evaluate(makeRecord({ verifier: CAROL }))).toBe('bad-signature')
  })

  it('a record whose fingerprint was edited after signing is bad-signature', () => {
    const rec = makeRecord()
    expect(evaluate({ ...rec, fingerprint: fingerprint(bob.publicKey, wrapB) })).toBe(
      'bad-signature',
    )
  })

  it('undecodable fields are bad-signature and never throw', () => {
    const rec = makeRecord()
    expect(evaluate({ ...rec, signature: '***' })).toBe('bad-signature')
    expect(evaluate({ ...rec, verifierSigningPublicKey: '***' })).toBe('bad-signature')
  })

  // v2: the day is signed, so a day edited after signing, a malformed day, or
  // a record signed under the v1 context must all fail, never read as none.
  it('a signed day changed after signing is bad-signature', () => {
    expect(evaluate({ ...makeRecord(), signedDay: '2026-10-20' })).toBe('bad-signature')
  })

  it.each(['yesterday', '2026-1-2', '2026-02-30', ''])(
    'a malformed signed day %j is bad-signature',
    (day) => {
      expect(evaluate(makeRecord({ day, recordedDay: day }))).toBe('bad-signature')
    },
  )

  it('a record signed under the v1 verification context is bad-signature', () => {
    const payload = verificationPayload(ME, BOB, me.publicKey, bobFp, DAY)
    const v1 = bytesToBase64(sign(me, 'underground-bb:verification:v1' as never, payload))
    expect(evaluate({ ...makeRecord(), signature: v1 })).toBe('bad-signature')
  })

  it('a verification does not verify as a pin signature', () => {
    // Domain separation: the same bytes signed under the pin context are not accepted.
    const payload = verificationPayload(ME, BOB, me.publicKey, bobFp, DAY)
    const rec: VerificationRecord = {
      ...makeRecord(),
      signature: bytesToBase64(sign(me, SigningContext.Pin, payload)),
    }
    expect(evaluate(rec)).toBe('bad-signature')
  })
})
