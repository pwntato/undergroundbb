// Round-trip test for #128's recovery flow, requested in PR #129 review:
// signup material -> completeRecovery with the real recovery code -> unwrap
// the new PROFILE blob with the new password -> same signing/wrapping keys
// as the original signup. Exercises generateSignupMaterial, completeRecovery,
// and the shared wrapNewCredentials together, against real Argon2id/AES-GCM,
// not mocks -- the same class of gap PR #127 round 1 found (an untested
// path silently using the wrong KDF input) only shows up when the actual
// derivations run end to end.

import { describe, expect, it } from 'vitest'
import { decrypt, KEY_SIZE } from './aesgcm.js'
import { deriveKey, type Argon2idParams } from './argon2.js'
import { base64ToBytes } from './base64.js'
import { credentialWrapAAD } from './credential.js'
import { completeRecovery, generateSignupMaterial } from './credential-material.js'
import { decodeKeyBundle, type KeyBundle } from './keybundle.js'
import { normalizeRecoveryCode } from './recovery-code.js'

const USER_ID = '11111111-1111-4111-8111-111111111111'

/** Unwraps a PROFILE-copy wrap with password, as completeLogin does internally. */
async function unwrapProfile(
  password: string,
  wrap: {
    readonly salt: string
    readonly argon2Params: Argon2idParams
    readonly wrappedPrivateKeys: { readonly nonce: string; readonly ciphertext: string }
  },
): Promise<KeyBundle> {
  const key = await deriveKey(password, base64ToBytes(wrap.salt), wrap.argon2Params, KEY_SIZE)
  const plaintext = await decrypt(
    key,
    base64ToBytes(wrap.wrappedPrivateKeys.nonce),
    base64ToBytes(wrap.wrappedPrivateKeys.ciphertext),
    credentialWrapAAD(USER_ID, 'PROFILE'),
  )
  return decodeKeyBundle(plaintext)
}

describe('recovery round trip', () => {
  it('redeems the signup recovery code and the new PROFILE wrap opens with the new password', async () => {
    const signup = await generateSignupMaterial(USER_ID, 'original-password', () => {})

    // Submits the hyphenated display form, exactly as generateRecoveryCode
    // produced it -- pinning that completeRecovery's own unwrap normalizes
    // internally (deriveRecoveryWrapKey does), so a caller handing it the
    // display form still works. RecoveryScreen normalizes earlier still, at
    // collection, but that's a property of the caller, not this function.
    const recovered = await completeRecovery(
      {
        recoveryCode: signup.recoveryCode,
        recoverySalt: signup.recoverySalt,
        recoveryArgon2Params: signup.recoveryArgon2Params,
        recoveryWrappedPrivateKeys: signup.recoveryWrappedPrivateKeys,
        userId: USER_ID,
        newPassword: 'new-password',
      },
      () => {},
    )

    const originalKeys = await unwrapProfile('original-password', signup)
    const newKeys = await unwrapProfile('new-password', recovered)

    // Same keypair as the original signup -- recovery re-wraps, it does not
    // rotate (#62 is the separate feature that would).
    expect(Array.from(newKeys.signingSeed)).toEqual(Array.from(originalKeys.signingSeed))
    expect(Array.from(newKeys.wrappingPrivateKey)).toEqual(
      Array.from(originalKeys.wrappingPrivateKey),
    )

    // The old password's wrap is untouched by this assertion, but the old
    // RECOVERY wrap is dead: the OLD code must not redeem the NEW recovery
    // wrap (wrapNewCredentials generated a fresh salt/code/verifier).
    await expect(
      completeRecovery(
        {
          recoveryCode: signup.recoveryCode,
          recoverySalt: recovered.recoverySalt,
          recoveryArgon2Params: recovered.recoveryArgon2Params,
          recoveryWrappedPrivateKeys: recovered.recoveryWrappedPrivateKeys,
          userId: USER_ID,
          newPassword: 'yet-another-password',
        },
        () => {},
      ),
    ).rejects.toThrow()

    // The NEW code, normalized as RecoveryScreen would submit it, does
    // redeem the NEW recovery wrap, and issues yet another fresh code.
    const secondRecovery = await completeRecovery(
      {
        recoveryCode: normalizeRecoveryCode(recovered.recoveryCode),
        recoverySalt: recovered.recoverySalt,
        recoveryArgon2Params: recovered.recoveryArgon2Params,
        recoveryWrappedPrivateKeys: recovered.recoveryWrappedPrivateKeys,
        userId: USER_ID,
        newPassword: 'yet-another-password',
      },
      () => {},
    )
    expect(secondRecovery.recoveryCode).not.toBe(recovered.recoveryCode)
  })

  it('fails when the recovery code is wrong', async () => {
    const signup = await generateSignupMaterial(USER_ID, 'original-password', () => {})

    await expect(
      completeRecovery(
        {
          recoveryCode: 'WRONG0-CODE0-00000-00000-000000',
          recoverySalt: signup.recoverySalt,
          recoveryArgon2Params: signup.recoveryArgon2Params,
          recoveryWrappedPrivateKeys: signup.recoveryWrappedPrivateKeys,
          userId: USER_ID,
          newPassword: 'new-password',
        },
        () => {},
      ),
    ).rejects.toThrow()
  })

  it('reports 4 progress steps: the unwrap, then wrapNewCredentials’s own 3', async () => {
    const signup = await generateSignupMaterial(USER_ID, 'original-password', () => {})

    const steps: { step: number; totalSteps: number }[] = []
    await completeRecovery(
      {
        recoveryCode: signup.recoveryCode,
        recoverySalt: signup.recoverySalt,
        recoveryArgon2Params: signup.recoveryArgon2Params,
        recoveryWrappedPrivateKeys: signup.recoveryWrappedPrivateKeys,
        userId: USER_ID,
        newPassword: 'new-password',
      },
      (event) => {
        steps.push({ step: event.step, totalSteps: event.totalSteps })
      },
    )

    expect(steps).toEqual([
      { step: 1, totalSteps: 4 },
      { step: 2, totalSteps: 4 },
      { step: 3, totalSteps: 4 },
      { step: 4, totalSteps: 4 },
    ])
  })
})
