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
import {
  completeChangePassword,
  completeLogin,
  completeRecovery,
  generateSignupMaterial,
  signGroupCreation,
} from './credential-material.js'
import * as ed25519 from './ed25519.js'
import { memberWrapAAD, roleGrantPayload, trustAnchorPayload } from './group.js'
import { decodeKeyBundle, type KeyBundle } from './keybundle.js'
import { normalizeRecoveryCode } from './recovery-code.js'
import { unwrap } from './x25519.js'

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

// #131's round trip, mirroring the recovery describe block above exactly:
// signup material -> completeChangePassword with the real old password ->
// unwrap the new PROFILE blob with the new password -> same signing/
// wrapping keys as the original signup. The one structural difference from
// completeRecovery: the unwrap here is keyed by the OLD PASSWORD against
// PROFILE's own salt/argon2Params/wrappedPrivateKeys (what GET
// /api/account/credentials returns), not a recovery code against a separate
// RECOVERY copy -- so there is no analogous "does the old wrap still
// redeem" case to pin; the old PROFILE wrap is simply overwritten, not left
// live under a stale key the way the RECOVERY copy's old code is.
describe('change-password round trip', () => {
  it('unwraps with the old password and the new PROFILE wrap opens with the new password', async () => {
    const signup = await generateSignupMaterial(USER_ID, 'original-password', () => {})

    const changed = await completeChangePassword(
      {
        oldPassword: 'original-password',
        salt: signup.salt,
        argon2Params: signup.argon2Params,
        wrappedPrivateKeys: signup.wrappedPrivateKeys,
        userId: USER_ID,
        newPassword: 'new-password',
      },
      () => {},
    )

    const originalKeys = await unwrapProfile('original-password', signup)
    const newKeys = await unwrapProfile('new-password', changed)

    // Same keypair as the original signup -- change-password re-wraps, it
    // does not rotate (#62 is the separate feature that would), same as
    // completeRecovery.
    expect(Array.from(newKeys.signingSeed)).toEqual(Array.from(originalKeys.signingSeed))
    expect(Array.from(newKeys.wrappingPrivateKey)).toEqual(
      Array.from(originalKeys.wrappingPrivateKey),
    )

    // A fresh recovery code was issued, distinct from signup's -- same
    // docs/DESIGN.md requirement completeRecovery's own round trip pins.
    expect(changed.recoveryCode).not.toBe(signup.recoveryCode)

    // The NEW recovery code redeems the NEW recovery wrap this call issued.
    const recovered = await completeRecovery(
      {
        recoveryCode: changed.recoveryCode,
        recoverySalt: changed.recoverySalt,
        recoveryArgon2Params: changed.recoveryArgon2Params,
        recoveryWrappedPrivateKeys: changed.recoveryWrappedPrivateKeys,
        userId: USER_ID,
        newPassword: 'yet-another-password',
      },
      () => {},
    )
    const recoveredKeys = await unwrapProfile('yet-another-password', recovered)
    expect(Array.from(recoveredKeys.signingSeed)).toEqual(Array.from(originalKeys.signingSeed))
  })

  it('fails when the old password is wrong', async () => {
    const signup = await generateSignupMaterial(USER_ID, 'original-password', () => {})

    await expect(
      completeChangePassword(
        {
          oldPassword: 'wrong-password',
          salt: signup.salt,
          argon2Params: signup.argon2Params,
          wrappedPrivateKeys: signup.wrappedPrivateKeys,
          userId: USER_ID,
          newPassword: 'new-password',
        },
        () => {},
      ),
    ).rejects.toThrow()
  })

  it('reports 4 progress steps: the old-password unwrap, then wrapNewCredentials’s own 3', async () => {
    const signup = await generateSignupMaterial(USER_ID, 'original-password', () => {})

    const steps: { step: number; totalSteps: number }[] = []
    await completeChangePassword(
      {
        oldPassword: 'original-password',
        salt: signup.salt,
        argon2Params: signup.argon2Params,
        wrappedPrivateKeys: signup.wrappedPrivateKeys,
        userId: USER_ID,
        newPassword: 'new-password',
      },
      (event) => {
        steps.push({ step: event.step, totalSteps: event.totalSteps })
      },
    )

    // Same shape as completeRecovery's 4 (its own upfront unwrap plus
    // wrapNewCredentials's 3) -- PR #132 review caught an earlier draft
    // that left this unwrap uncounted at 3, which silently changed
    // SignupProgressStep's total mid-flow (the exact PR #129 regression its
    // own doc comment warns against).
    expect(steps).toEqual([
      { step: 1, totalSteps: 4 },
      { step: 2, totalSteps: 4 },
      { step: 3, totalSteps: 4 },
      { step: 4, totalSteps: 4 },
    ])
  })
})

// Issue #34: proves signGroupCreation's output actually verifies/unwraps
// against the SAME keypair completeLogin unwraps from a real signup -- the
// gap the vector tests alone don't cover, since those exercise
// trustAnchorPayload/roleGrantPayload/memberWrapAAD in isolation against
// fixed inputs, never against a keypair that came out of a real
// signup -> login round trip the way worker.ts's liveKeys cache actually
// does.
describe('group creation signing', () => {
  it('signs a verifiable trust anchor and root grant, and wraps a recoverable group key', async () => {
    const signup = await generateSignupMaterial(USER_ID, 'group-creator-password', () => {})

    const { keys } = await completeLogin({
      password: 'group-creator-password',
      salt: signup.salt,
      argon2Params: signup.argon2Params,
      wrappedPrivateKeys: signup.wrappedPrivateKeys,
      userId: USER_ID,
      nonce: Buffer.from([1, 2, 3, 4]).toString('base64'),
    })
    expect(keys.userId).toBe(USER_ID)

    const groupId = 'group-uuid-test-1'
    const groupKey = new Uint8Array(32).fill(7)

    const result = await signGroupCreation(keys, groupId, groupKey)

    const anchorPayload = trustAnchorPayload(USER_ID, keys.signingKey.publicKey, groupId)
    expect(
      ed25519.verify(
        keys.signingKey.publicKey,
        ed25519.SigningContext.TrustAnchor,
        anchorPayload,
        base64ToBytes(result.trustAnchorSignature),
      ),
    ).toBe(true)

    const grantPayload = roleGrantPayload(groupId, USER_ID, 'admin', '')
    expect(
      ed25519.verify(
        keys.signingKey.publicKey,
        ed25519.SigningContext.RoleGrant,
        grantPayload,
        base64ToBytes(result.rootGrantSignature),
      ),
    ).toBe(true)

    // The creator can unwrap their own wrapped group key with their own
    // wrapping private key and the correct AAD -- the actual round trip
    // this whole function exists to make possible, and the bug this test
    // was added to catch: an earlier draft dropped groupKeyWrapped's
    // ephemeralPub entirely, which made this unwrap always fail.
    const wrapAAD = memberWrapAAD(groupId, USER_ID, 0)
    const unwrapped = await unwrap(
      keys.wrappingKey.privateKey,
      {
        ephemeralPub: base64ToBytes(result.groupKeyWrapped.ephemeralPub),
        nonce: base64ToBytes(result.groupKeyWrapped.nonce),
        ciphertext: base64ToBytes(result.groupKeyWrapped.ciphertext),
      },
      wrapAAD,
    )
    expect(unwrapped).toEqual(groupKey)

    // Unwrapping under a DIFFERENT group id's AAD must fail -- proves the
    // wrap is actually bound to this group and member, not merely present.
    const wrongAad = memberWrapAAD('a-different-group', USER_ID, 0)
    await expect(
      unwrap(
        keys.wrappingKey.privateKey,
        {
          ephemeralPub: base64ToBytes(result.groupKeyWrapped.ephemeralPub),
          nonce: base64ToBytes(result.groupKeyWrapped.nonce),
          ciphertext: base64ToBytes(result.groupKeyWrapped.ciphertext),
        },
        wrongAad,
      ),
    ).rejects.toThrow()
  })
})
