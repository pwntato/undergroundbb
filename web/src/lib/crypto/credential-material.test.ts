// Round-trip test for #128's recovery flow, requested in PR #129 review:
// signup material -> completeRecovery with the real recovery code -> unwrap
// the new PROFILE blob with the new password -> same signing/wrapping keys
// as the original signup. Exercises generateSignupMaterial, completeRecovery,
// and the shared wrapNewCredentials together, against real Argon2id/AES-GCM,
// not mocks -- the same class of gap PR #127 round 1 found (an untested
// path silently using the wrong KDF input) only shows up when the actual
// derivations run end to end.

import { describe, expect, it } from 'vitest'
import { decrypt, encrypt, KEY_SIZE } from './aesgcm.js'
import { deriveKey, type Argon2idParams } from './argon2.js'
import { base64ToBytes, bytesToBase64 } from './base64.js'
import { credentialWrapAAD } from './credential.js'
import {
  completeChangePassword,
  completeInvite,
  completeLogin,
  completeRecovery,
  decryptGroupNames,
  encryptGroupText,
  generateSignupMaterial,
  InviteMACError,
  rewrapGroupKey,
  signGroupCreation,
  signInviteAcceptance,
  signInviteCreation,
  signPin,
  signRoleGrant,
  signSuccessorClaim,
  signSuccessorDesignation,
  startGroupRotation,
} from './credential-material.js'
import * as ed25519 from './ed25519.js'
import {
  admissionPayload,
  genKeyAAD,
  groupNameAAD,
  memberWrapAAD,
  roleGrantPayload,
  rotationStartPayload,
  successorClaimPayload,
  successorDesignationPayload,
  trustAnchorPayload,
} from './group.js'
import {
  computeInviteMAC,
  deriveInviteMACKey,
  inviteAcceptancePayload,
  inviteCreationPayload,
} from './invite.js'
import { decodeKeyBundle, type KeyBundle } from './keybundle.js'
import { normalizeRecoveryCode } from './recovery-code.js'
import { evaluatePin } from './pin.js'
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

    expect(result.rootGrantSortKey).toContain(`GRANT#${USER_ID}#`)
    const grantPayload = roleGrantPayload(groupId, USER_ID, 'admin', result.rootGrantSortKey, '')
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

// Issue #35: decryptGroupNames is the group-list read path's counterpart to
// signGroupCreation's write path -- this proves it actually recovers a
// name/description that was wrapped/encrypted the same way a real private
// group's META and the member's own MEMBER# item would be, and that one
// corrupt entry in a batch does not take down the rest (DecryptGroupNames
// Response's own doc comment on the protocol side).
describe('decryptGroupNames', () => {
  async function realMemberKeys() {
    const signup = await generateSignupMaterial(USER_ID, 'group-member-password', () => {})
    const { keys } = await completeLogin({
      password: 'group-member-password',
      salt: signup.salt,
      argon2Params: signup.argon2Params,
      wrappedPrivateKeys: signup.wrappedPrivateKeys,
      userId: USER_ID,
      nonce: Buffer.from([9, 9, 9, 9]).toString('base64'),
    })
    return keys
  }

  // signGroupCreation wraps groupKey at Generation 0 -- the only generation
  // this codebase can produce today (rotation is #78, unbuilt) -- so every
  // caller here uses generation 0 throughout, matching the wrap this
  // function produces.
  async function setUpMemberWithGroup(
    groupId: string,
    groupKey: Uint8Array,
    existingKeys?: Awaited<ReturnType<typeof realMemberKeys>>,
  ) {
    const keys = existingKeys ?? (await realMemberKeys())
    // signGroupCreation is reused purely for its wrap of groupKey to this
    // member's own wrapping key under memberWrapAAD -- the exact shape a
    // real MEMBER# item's WrappedGroupKey has, whether this member created
    // the group or merely joined it (the wrap itself doesn't know which).
    const signed = await signGroupCreation(keys, groupId, groupKey)
    return { keys, wrappedGroupKey: signed.groupKeyWrapped }
  }

  it('recovers the name and description a real wrap+encrypt produced', async () => {
    const groupId = 'group-uuid-test-2'
    const generation = 0
    const groupKey = new Uint8Array(32).fill(3)
    const { keys, wrappedGroupKey } = await setUpMemberWithGroup(groupId, groupKey)

    const nameEnc = await encrypt(
      groupKey,
      new TextEncoder().encode('Roof Group'),
      groupNameAAD(groupId, 'NAME', generation),
    )
    const descEnc = await encrypt(
      groupKey,
      new TextEncoder().encode('Talking about the roof'),
      groupNameAAD(groupId, 'DESC', generation),
    )

    const results = await decryptGroupNames(keys, [
      {
        groupId,
        generation,
        nameGeneration: generation,
        wrappedGroupKey,
        nameCiphertext: {
          nonce: bytesToBase64(nameEnc.nonce),
          ciphertext: bytesToBase64(nameEnc.ciphertext),
        },
        descriptionCiphertext: {
          nonce: bytesToBase64(descEnc.nonce),
          ciphertext: bytesToBase64(descEnc.ciphertext),
        },
      },
    ])

    expect(results).toEqual([
      { groupId, name: 'Roof Group', description: 'Talking about the roof' },
    ])
  })

  // The chain tests mint real links with startGroupRotation (the code that
  // writes them in production), so a walk that disagrees with the writer on the
  // key, the AAD or the direction fails here rather than against a fixture.
  async function rotatedGroup(rotations: number) {
    const groupId = 'group-uuid-test-chain'
    const keyAtGeneration0 = new Uint8Array(32).fill(8)
    const { keys, wrappedGroupKey } = await setUpMemberWithGroup(groupId, keyAtGeneration0)
    const fromWire = (w: { ephemeralPub: string; nonce: string; ciphertext: string }) => ({
      ephemeralPub: base64ToBytes(w.ephemeralPub),
      nonce: base64ToBytes(w.nonce),
      ciphertext: base64ToBytes(w.ciphertext),
    })
    let own = wrappedGroupKey
    const chain: { generation: number; wrapped: { nonce: string; ciphertext: string } }[] = []
    for (let generation = 0; generation < rotations; generation++) {
      const step = await startGroupRotation(keys, groupId, fromWire(own), generation, 'subject-id')
      chain.push({ generation, wrapped: step.link })
      own = step.removerWrappedKey
    }
    const enc = async (field: 'NAME' | 'DESC', text: string, generation: number) => {
      const sealed = await encrypt(
        keyAtGeneration0,
        new TextEncoder().encode(text),
        groupNameAAD(groupId, field, generation),
      )
      return { nonce: bytesToBase64(sealed.nonce), ciphertext: bytesToBase64(sealed.ciphertext) }
    }
    const entry = {
      groupId,
      generation: rotations,
      nameGeneration: 0,
      wrappedGroupKey: own,
      nameCiphertext: await enc('NAME', 'Renamed', 0),
      descriptionCiphertext: await enc('DESC', 'Described', 0),
    }
    return { keys, entry, chain }
  }

  it('walks the chain back to the generation the name was sealed under', async () => {
    const { keys, entry, chain } = await rotatedGroup(2)
    expect(await decryptGroupNames(keys, [{ ...entry, chain }])).toEqual([
      { groupId: entry.groupId, name: 'Renamed', description: 'Described' },
    ])
  })

  it('accepts the links in any order', async () => {
    const { keys, entry, chain } = await rotatedGroup(2)
    expect(await decryptGroupNames(keys, [{ ...entry, chain: [...chain].reverse() }])).toEqual([
      { groupId: entry.groupId, name: 'Renamed', description: 'Described' },
    ])
  })

  it('reports the name unreadable when a link is missing', async () => {
    const { keys, entry, chain } = await rotatedGroup(2)
    const gap = chain.filter((l) => l.generation !== 0)
    expect(await decryptGroupNames(keys, [{ ...entry, chain: gap }])).toEqual([
      { groupId: entry.groupId, name: null, description: null },
    ])
    expect(await decryptGroupNames(keys, [entry])).toEqual([
      { groupId: entry.groupId, name: null, description: null },
    ])
  })

  it('reports the name unreadable when a link was tampered with or relabeled', async () => {
    const { keys, entry, chain } = await rotatedGroup(2)
    const flipped = chain.map((l) =>
      l.generation === 1
        ? { ...l, wrapped: { ...l.wrapped, ciphertext: bytesToBase64(new Uint8Array(48)) } }
        : l,
    )
    expect(await decryptGroupNames(keys, [{ ...entry, chain: flipped }])).toEqual([
      { groupId: entry.groupId, name: null, description: null },
    ])
    // Swapping the two links' generations breaks their AAD binding.
    const relabeled = chain.map((l) => ({ ...l, generation: 1 - l.generation }))
    expect(await decryptGroupNames(keys, [{ ...entry, chain: relabeled }])).toEqual([
      { groupId: entry.groupId, name: null, description: null },
    ])
  })

  it('does not use the member generation as the name generation', async () => {
    const { keys, entry, chain } = await rotatedGroup(2)
    // Claiming the name is at the member's own generation skips the walk and
    // must fail, not succeed with the wrong key.
    expect(await decryptGroupNames(keys, [{ ...entry, nameGeneration: 2, chain }])).toEqual([
      { groupId: entry.groupId, name: null, description: null },
    ])
  })

  it('reports a name from a newer generation than the member holds as unreadable', async () => {
    const { keys, entry, chain } = await rotatedGroup(2)
    expect(
      await decryptGroupNames(keys, [{ ...entry, generation: 0, nameGeneration: 2, chain }]),
    ).toEqual([{ groupId: entry.groupId, name: null, description: null }])
  })

  it('encryptGroupText output round-trips through decryptGroupNames', async () => {
    const groupId = 'group-uuid-test-edit'
    const groupKey = new Uint8Array(32).fill(9)
    const { keys, wrappedGroupKey } = await setUpMemberWithGroup(groupId, groupKey)

    const sealed = await encryptGroupText(keys, {
      groupId,
      generation: 0,
      nameGeneration: 0,
      wrappedGroupKey,
      name: 'New Name',
      description: 'New description',
    })
    expect(
      await decryptGroupNames(keys, [
        { groupId, generation: 0, nameGeneration: 0, wrappedGroupKey, ...sealed },
      ]),
    ).toEqual([{ groupId, name: 'New Name', description: 'New description' }])

    // Fresh nonce per call: identical plaintext must not reuse one.
    const again = await encryptGroupText(keys, {
      groupId,
      generation: 0,
      nameGeneration: 0,
      wrappedGroupKey,
      name: 'New Name',
      description: 'New description',
    })
    expect(again.nameCiphertext.nonce).not.toEqual(sealed.nameCiphertext.nonce)
  })

  it('encryptGroupText rejects rather than returning half a result on a bad wrap', async () => {
    const groupId = 'group-uuid-test-edit-bad'
    const { keys } = await setUpMemberWithGroup(groupId, new Uint8Array(32).fill(10))
    const other = await setUpMemberWithGroup('some-other-group', new Uint8Array(32).fill(11), keys)

    // A wrap made for a different group id fails the member-wrap AAD.
    await expect(
      encryptGroupText(keys, {
        groupId,
        generation: 0,
        nameGeneration: 0,
        wrappedGroupKey: other.wrappedGroupKey,
        name: 'x',
        description: 'y',
      }),
    ).rejects.toThrow()
  })

  it('returns null fields for one bad entry without failing the rest of the batch', async () => {
    // Both groups belong to the SAME member (one real caller's batch, one
    // worker call covering their whole group list) -- only the bad entry's
    // ciphertext is wrong, isolating the failure to the decrypt step rather
    // than also failing to unwrap the group key at all.
    const goodGroupId = 'group-uuid-test-good'
    const badGroupId = 'group-uuid-test-bad'
    const generation = 0
    const goodKey = new Uint8Array(32).fill(5)
    const badKey = new Uint8Array(32).fill(6)

    const good = await setUpMemberWithGroup(goodGroupId, goodKey)
    const bad = await setUpMemberWithGroup(badGroupId, badKey, good.keys)

    const goodNameEnc = await encrypt(
      goodKey,
      new TextEncoder().encode('Good Group'),
      groupNameAAD(goodGroupId, 'NAME', generation),
    )
    const goodDescEnc = await encrypt(
      goodKey,
      new TextEncoder().encode('Fine'),
      groupNameAAD(goodGroupId, 'DESC', generation),
    )
    // Encrypted under the WRONG group id's AAD -- simulates corrupt/stale
    // ciphertext (e.g. a generation mismatch after a rotation this client
    // hasn't caught up on), which must fail this one entry only. The
    // wrapped group key itself unwraps fine; only the name/description
    // ciphertext is bad, isolating the failure to decryptGroupText.
    const badNameEnc = await encrypt(
      badKey,
      new TextEncoder().encode('Bad Group'),
      groupNameAAD('a-completely-different-group', 'NAME', generation),
    )
    const badDescEnc = await encrypt(
      badKey,
      new TextEncoder().encode('Corrupt'),
      groupNameAAD('a-completely-different-group', 'DESC', generation),
    )

    const results = await decryptGroupNames(good.keys, [
      {
        groupId: goodGroupId,
        generation,
        nameGeneration: generation,
        wrappedGroupKey: good.wrappedGroupKey,
        nameCiphertext: {
          nonce: bytesToBase64(goodNameEnc.nonce),
          ciphertext: bytesToBase64(goodNameEnc.ciphertext),
        },
        descriptionCiphertext: {
          nonce: bytesToBase64(goodDescEnc.nonce),
          ciphertext: bytesToBase64(goodDescEnc.ciphertext),
        },
      },
      {
        groupId: badGroupId,
        generation,
        nameGeneration: generation,
        wrappedGroupKey: bad.wrappedGroupKey,
        nameCiphertext: {
          nonce: bytesToBase64(badNameEnc.nonce),
          ciphertext: bytesToBase64(badNameEnc.ciphertext),
        },
        descriptionCiphertext: {
          nonce: bytesToBase64(badDescEnc.nonce),
          ciphertext: bytesToBase64(badDescEnc.ciphertext),
        },
      },
    ])

    expect(results).toEqual([
      { groupId: goodGroupId, name: 'Good Group', description: 'Fine' },
      { groupId: badGroupId, name: null, description: null },
    ])
  })
})

// Issues #38/#39/#40: the invite handshake's full round trip against real
// keypairs from real signup->login flows -- the same class of gap
// vectors.test.ts's fixed-input tests cannot cover (those pin the payload
// ENCODING; this proves the whole ceremony actually delivers a working
// group key end to end, mirroring "group creation signing" above but for
// two distinct accounts playing inviter and invitee).
describe('invite handshake round trip', () => {
  const INVITER_ID = '22222222-2222-4222-8222-222222222222'
  const INVITEE_ID = '33333333-3333-4333-8333-333333333333'
  const ADMISSION_GRANT_REF = `GRANT#${INVITER_ID}#2026-09-06#a1b2c3d4e5f6a1b2`
  const ADMISSION_DAY = '2026-10-07'

  async function realUserKeys(userId: string, password: string) {
    const signup = await generateSignupMaterial(userId, password, () => {})
    const { keys } = await completeLogin({
      password,
      salt: signup.salt,
      argon2Params: signup.argon2Params,
      wrappedPrivateKeys: signup.wrappedPrivateKeys,
      userId,
      nonce: Buffer.from([5, 5, 5, 5]).toString('base64'),
    })
    return keys
  }

  it('signs a verifiable step-1 creation payload', async () => {
    const inviter = await realUserKeys(INVITER_ID, 'inviter-password')
    const inviteId = 'invite-uuid-test-1'
    const groupId = 'group-uuid-test-3'
    const expiresAt = '2026-10-03T00:00:00Z'

    const result = await signInviteCreation(inviter, inviteId, groupId, expiresAt)

    const payload = inviteCreationPayload(
      inviteId,
      groupId,
      inviter.signingKey.publicKey,
      expiresAt,
    )
    expect(
      ed25519.verify(
        inviter.signingKey.publicKey,
        ed25519.SigningContext.Invite,
        payload,
        base64ToBytes(result.creationSignature),
      ),
    ).toBe(true)
  })

  it("signs a verifiable step-2 acceptance payload binding the invitee's own current keys", async () => {
    const invitee = await realUserKeys(INVITEE_ID, 'invitee-password')
    const inviteId = 'invite-uuid-test-2'
    const macKey = new Uint8Array(32).fill(7)

    const result = await signInviteAcceptance(invitee, inviteId, macKey)

    const payload = inviteAcceptancePayload(
      inviteId,
      invitee.signingKey.publicKey,
      invitee.wrappingKey.publicKey,
    )
    expect(
      ed25519.verify(
        invitee.signingKey.publicKey,
        ed25519.SigningContext.Invite,
        payload,
        base64ToBytes(result.acceptanceSignature),
      ),
    ).toBe(true)

    // A signature over a DIFFERENT invite id must not verify against this
    // payload -- proves the signature is actually bound to this invite,
    // not merely present.
    const wrongPayload = inviteAcceptancePayload(
      'a-different-invite-id',
      invitee.signingKey.publicKey,
      invitee.wrappingKey.publicKey,
    )
    expect(
      ed25519.verify(
        invitee.signingKey.publicKey,
        ed25519.SigningContext.Invite,
        wrongPayload,
        base64ToBytes(result.acceptanceSignature),
      ),
    ).toBe(false)

    // inviteMAC must be MAC_k(payload) under the SAME macKey the caller
    // (the real invite link's fragment, in production) supplied -- not
    // some other value derived independently.
    expect(base64ToBytes(result.inviteMAC)).toEqual(computeInviteMAC(macKey, payload))
  })

  // The full three-step ceremony: inviter creates a group and wraps its own
  // key (reusing signGroupCreation exactly as setUpMemberWithGroup does
  // above), invitee signs step 2 with their OWN real keys, inviter's
  // completeInvite unwraps its own copy and re-wraps to the invitee's real
  // X25519 public key -- and the invitee can actually unwrap the result
  // with their own real private key. This is the property the whole
  // handshake exists to deliver; nothing short of an end-to-end run with
  // two real keypairs can prove it.
  it('delivers a group key the invitee can actually unwrap, wrapped to the keys they signed', async () => {
    const inviter = await realUserKeys(INVITER_ID, 'inviter-password-2')
    const invitee = await realUserKeys(INVITEE_ID, 'invitee-password-2')
    const groupId = 'group-uuid-test-4'
    const groupKey = new Uint8Array(32).fill(9)

    const created = await signGroupCreation(inviter, groupId, groupKey)
    const ownWrappedGroupKey = {
      ephemeralPub: base64ToBytes(created.groupKeyWrapped.ephemeralPub),
      nonce: base64ToBytes(created.groupKeyWrapped.nonce),
      ciphertext: base64ToBytes(created.groupKeyWrapped.ciphertext),
    }

    const inviteId = 'invite-uuid-test-3'
    // The real link-holder's macKey, as it would arrive via the invite
    // link's own URL fragment -- derived here from the INVITER's real
    // seed, exactly as signInviteCreation does, so this test exercises the
    // real end-to-end derivation rather than an arbitrary shared secret.
    const macKey = deriveInviteMACKey(inviter.signingKey.seed, inviteId)
    const acceptance = await signInviteAcceptance(invitee, inviteId, macKey)
    // The inviter's client re-verifies the invitee's acceptance signature
    // before ever calling completeInvite -- see worker.ts's own doc
    // comment on why that check happens in the caller, not inside
    // completeInvite itself.
    const acceptancePayload = inviteAcceptancePayload(
      inviteId,
      invitee.signingKey.publicKey,
      invitee.wrappingKey.publicKey,
    )
    expect(
      ed25519.verify(
        invitee.signingKey.publicKey,
        ed25519.SigningContext.Invite,
        acceptancePayload,
        base64ToBytes(acceptance.acceptanceSignature),
      ),
    ).toBe(true)

    const completed = await completeInvite(
      inviter,
      inviteId,
      groupId,
      ownWrappedGroupKey,
      0,
      INVITEE_ID,
      invitee.signingKey.publicKey,
      invitee.wrappingKey.publicKey,
      base64ToBytes(acceptance.inviteMAC),
      ADMISSION_GRANT_REF,
      ADMISSION_DAY,
    )
    expect(completed.generation).toBe(0)

    // The inviter signed an admission of exactly the keys the invitee signed,
    // under the grant ref and day it was handed (#178). A verifier rebuilds
    // the payload from the stored record, so it must verify under the
    // inviter's key and under no other context.
    const admission = admissionPayload(
      groupId,
      INVITER_ID,
      INVITEE_ID,
      invitee.signingKey.publicKey,
      invitee.wrappingKey.publicKey,
      inviteId,
      ADMISSION_GRANT_REF,
      ADMISSION_DAY,
      completed.generation,
    )
    expect(completed.admission.inviterGrantRef).toBe(ADMISSION_GRANT_REF)
    expect(completed.admission.day).toBe(ADMISSION_DAY)
    const admissionSig = base64ToBytes(completed.admission.signature)
    expect(
      ed25519.verify(
        inviter.signingKey.publicKey,
        ed25519.SigningContext.Admission,
        admission,
        admissionSig,
      ),
    ).toBe(true)
    expect(
      ed25519.verify(
        inviter.signingKey.publicKey,
        ed25519.SigningContext.RoleGrant,
        admission,
        admissionSig,
      ),
    ).toBe(false)
    expect(
      ed25519.verify(
        invitee.signingKey.publicKey,
        ed25519.SigningContext.Admission,
        admission,
        admissionSig,
      ),
    ).toBe(false)

    // The invitee can now unwrap THEIR OWN copy with their own real
    // wrapping private key and the AAD their future MEMBER# item carries.
    const inviteeUnwrapAAD = memberWrapAAD(groupId, INVITEE_ID, 0)
    const unwrapped = await unwrap(
      invitee.wrappingKey.privateKey,
      {
        ephemeralPub: base64ToBytes(completed.wrappedGroupKey.ephemeralPub),
        nonce: base64ToBytes(completed.wrappedGroupKey.nonce),
        ciphertext: base64ToBytes(completed.wrappedGroupKey.ciphertext),
      },
      inviteeUnwrapAAD,
    )
    expect(unwrapped).toEqual(groupKey)

    // The INVITER's own private key must NOT be able to unwrap the
    // invitee's copy -- it was wrapped to a different X25519 public key
    // entirely, so this proves completeInvite actually re-wrapped to the
    // invitee rather than, say, silently reusing the inviter's own wrap.
    await expect(
      unwrap(
        inviter.wrappingKey.privateKey,
        {
          ephemeralPub: base64ToBytes(completed.wrappedGroupKey.ephemeralPub),
          nonce: base64ToBytes(completed.wrappedGroupKey.nonce),
          ciphertext: base64ToBytes(completed.wrappedGroupKey.ciphertext),
        },
        inviteeUnwrapAAD,
      ),
    ).rejects.toThrow()

    // Unwrapping under the INVITER's own AAD (wrong member uuid) must also
    // fail, even with the invitee's own correct private key -- proves the
    // wrap is bound to the invitee's identity, not just their key.
    const wrongAad = memberWrapAAD(groupId, INVITER_ID, 0)
    await expect(
      unwrap(
        invitee.wrappingKey.privateKey,
        {
          ephemeralPub: base64ToBytes(completed.wrappedGroupKey.ephemeralPub),
          nonce: base64ToBytes(completed.wrappedGroupKey.nonce),
          ciphertext: base64ToBytes(completed.wrappedGroupKey.ciphertext),
        },
        wrongAad,
      ),
    ).rejects.toThrow()
  })

  // This is the actual defect PR #146's round-1 review found: a malicious
  // server can mint its own Ed25519/X25519 keypair, self-sign a step-2
  // payload under crypto.ContextInvite, and serve that as if it came from
  // the real invitee. Plain signature verification (the block above)
  // cannot catch this -- the keys and the signature are mutually
  // consistent, which is all that check proves. completeInvite's own
  // inviteMAC check is what must catch it instead.
  it('refuses to complete when inviteMAC does not verify (a malicious server substituting its own keypair)', async () => {
    const inviter = await realUserKeys(INVITER_ID, 'inviter-password-3')
    const groupId = 'group-uuid-test-5'
    const groupKey = new Uint8Array(32).fill(3)

    const created = await signGroupCreation(inviter, groupId, groupKey)
    const ownWrappedGroupKey = {
      ephemeralPub: base64ToBytes(created.groupKeyWrapped.ephemeralPub),
      nonce: base64ToBytes(created.groupKeyWrapped.nonce),
      ciphertext: base64ToBytes(created.groupKeyWrapped.ciphertext),
    }

    const inviteId = 'invite-uuid-test-5'

    // A malicious server's own freshly minted keypair -- NOT the real
    // invite link-holder's, and never handed the real macKey (which
    // travelled only in the link's fragment, which this "server" never
    // saw either).
    const forgedSigningKey = ed25519.generateSigningKey()
    const forgedWrappingKey = {
      privateKey: new Uint8Array(32).fill(5),
      publicKey: new Uint8Array(32).fill(6),
    }
    const forgedPayload = inviteAcceptancePayload(
      inviteId,
      forgedSigningKey.publicKey,
      forgedWrappingKey.publicKey,
    )
    const forgedSignature = ed25519.sign(
      forgedSigningKey,
      ed25519.SigningContext.Invite,
      forgedPayload,
    )
    // The forged signature DOES verify -- proving this scenario would slip
    // straight past runCompleteInvites.ts's own Ed25519 check with no MAC
    // involved at all.
    expect(
      ed25519.verify(
        forgedSigningKey.publicKey,
        ed25519.SigningContext.Invite,
        forgedPayload,
        forgedSignature,
      ),
    ).toBe(true)

    // The server has no way to produce a valid inviteMAC (it never had the
    // real macKey), so it can only ever serve a wrong one -- modeled here
    // as a MAC computed under an unrelated key.
    const wrongMacKey = new Uint8Array(32).fill(0xff)
    const forgedMAC = computeInviteMAC(wrongMacKey, forgedPayload)

    await expect(
      completeInvite(
        inviter,
        inviteId,
        groupId,
        ownWrappedGroupKey,
        0,
        INVITEE_ID,
        forgedSigningKey.publicKey,
        forgedWrappingKey.publicKey,
        forgedMAC,
        ADMISSION_GRANT_REF,
        ADMISSION_DAY,
      ),
    ).rejects.toThrow(InviteMACError)
  })
})

describe('signRoleGrant', () => {
  const GROUP_ID = '44444444-4444-4444-8444-444444444444'
  const SUBJECT_ID = '55555555-5555-4555-8555-555555555555'
  const GRANTOR_REF = 'GRANT#11111111-1111-4111-8111-111111111111#2026-09-29#aaaaaaaaaaaaaaaa'

  async function grantorKeys() {
    const signup = await generateSignupMaterial(USER_ID, 'grantor-password', () => {})
    const { keys } = await completeLogin({
      password: 'grantor-password',
      salt: signup.salt,
      argon2Params: signup.argon2Params,
      wrappedPrivateKeys: signup.wrappedPrivateKeys,
      userId: USER_ID,
      nonce: Buffer.from([5, 5, 5, 5]).toString('base64'),
    })
    return keys
  }

  it('signs a verifiable payload binding the subject, role, its own address and the grantor ref', async () => {
    const keys = await grantorKeys()
    const { grantSortKey, signature } = signRoleGrant(
      keys,
      GROUP_ID,
      SUBJECT_ID,
      'ambassador',
      GRANTOR_REF,
    )

    expect(grantSortKey.startsWith(`GRANT#${SUBJECT_ID}#`)).toBe(true)
    const verifies = (role: string, ref: string, sortKey: string) =>
      ed25519.verify(
        keys.signingKey.publicKey,
        ed25519.SigningContext.RoleGrant,
        roleGrantPayload(GROUP_ID, SUBJECT_ID, role, sortKey, ref),
        base64ToBytes(signature),
      )
    expect(verifies('ambassador', GRANTOR_REF, grantSortKey)).toBe(true)
    // Each bound field really is bound: change any one and it must not verify.
    expect(verifies('admin', GRANTOR_REF, grantSortKey)).toBe(false)
    expect(verifies('ambassador', 'GRANT#other', grantSortKey)).toBe(false)
    expect(verifies('ambassador', GRANTOR_REF, `${grantSortKey}x`)).toBe(false)
  })

  it('generates a fresh grant address on every call', async () => {
    const keys = await grantorKeys()
    const a = signRoleGrant(keys, GROUP_ID, SUBJECT_ID, 'member', GRANTOR_REF)
    const b = signRoleGrant(keys, GROUP_ID, SUBJECT_ID, 'member', GRANTOR_REF)
    expect(a.grantSortKey).not.toBe(b.grantSortKey)
  })
})

describe('signPin', () => {
  const PINNER = '66666666-6666-4666-8666-666666666666'
  const PINNED = '77777777-7777-4777-8777-777777777777'

  // Uses a hand-built LiveKeys: signPin only reads userId and signingKey, and
  // skipping Argon2 keeps this off the slow path (#163).
  it('signs a pin that evaluatePin accepts under the same key, and only that key', () => {
    const signingKey = ed25519.generateSigningKey()
    const keys = { userId: PINNER, signingKey, wrappingKey: undefined as never }
    const bob = ed25519.generateSigningKey()
    const wrapping = new Uint8Array(32).fill(8)
    const { pinnerSigningPublicKey, signature } = signPin(keys, PINNED, [bob.publicKey], wrapping)
    expect(pinnerSigningPublicKey).toBe(bytesToBase64(signingKey.publicKey))

    const pin = {
      pinnedUserId: PINNED,
      signingPublicKeys: [bytesToBase64(bob.publicKey)],
      wrappingPublicKey: bytesToBase64(wrapping),
      pinnerSigningPublicKey,
      signature,
    }
    const served = {
      signingPublicKey: bytesToBase64(bob.publicKey),
      supersededSigningKeys: [],
      wrappingPublicKey: bytesToBase64(wrapping),
    }
    const run = (own: Uint8Array, id = PINNER) =>
      evaluatePin({
        pinnerUserId: id,
        pinnerSigningPublicKey: own,
        pinnedUserId: PINNED,
        pin,
        served,
      })
    expect(run(signingKey.publicKey)).toBe('match')
    expect(run(ed25519.generateSigningKey().publicKey)).toBe('bad-signature')
    expect(run(signingKey.publicKey, PINNED)).toBe('bad-signature')
  })
})

describe('group key rotation (#58)', () => {
  const ADMIN_ID = '44444444-4444-4444-8444-444444444444'
  const CAROL_ID = '55555555-5555-4555-8555-555555555555'
  const GROUP_ID = 'group-uuid-rotation-1'

  async function realUserKeys(userId: string, password: string) {
    const signup = await generateSignupMaterial(userId, password, () => {})
    const { keys } = await completeLogin({
      password,
      salt: signup.salt,
      argon2Params: signup.argon2Params,
      wrappedPrivateKeys: signup.wrappedPrivateKeys,
      userId,
      nonce: Buffer.from([6, 6, 6, 6]).toString('base64'),
    })
    return keys
  }

  const wire = (w: { ephemeralPub: string; nonce: string; ciphertext: string }) => ({
    ephemeralPub: base64ToBytes(w.ephemeralPub),
    nonce: base64ToBytes(w.nonce),
    ciphertext: base64ToBytes(w.ciphertext),
  })

  const SUBJECT_ID = 'removed-member-id'

  async function startedRotation() {
    const admin = await realUserKeys(ADMIN_ID, 'admin-password-rot')
    const oldKey = new Uint8Array(32).fill(7)
    const created = await signGroupCreation(admin, GROUP_ID, oldKey)
    const started = await startGroupRotation(
      admin,
      GROUP_ID,
      wire(created.groupKeyWrapped),
      0,
      SUBJECT_ID,
    )
    return { admin, oldKey, started }
  }

  it('mints generation+1 whose chain link walks back to the old key', async () => {
    const { admin, oldKey, started } = await startedRotation()
    expect(started.generation).toBe(1)

    // The remover's own entry is at the new generation and yields the NEW key.
    const newKey = await unwrap(
      admin.wrappingKey.privateKey,
      wire(started.removerWrappedKey),
      memberWrapAAD(GROUP_ID, ADMIN_ID, 1),
    )
    expect(newKey).toHaveLength(32)
    expect(newKey).not.toEqual(oldKey)

    // The link holds the OLD key under the NEW one, bound to generation 0.
    const link = {
      nonce: base64ToBytes(started.link.nonce),
      ciphertext: base64ToBytes(started.link.ciphertext),
    }
    const walked = await decrypt(newKey, link.nonce, link.ciphertext, genKeyAAD(GROUP_ID, 0))
    expect(walked).toEqual(oldKey)

    // A holder of only the old key cannot open it (the chain only walks back),
    // and the link is bound to its generation and group.
    await expect(
      decrypt(oldKey, link.nonce, link.ciphertext, genKeyAAD(GROUP_ID, 0)),
    ).rejects.toThrow()
    await expect(
      decrypt(newKey, link.nonce, link.ciphertext, genKeyAAD(GROUP_ID, 1)),
    ).rejects.toThrow()
    await expect(
      decrypt(newKey, link.nonce, link.ciphertext, genKeyAAD('other-group', 0)),
    ).rejects.toThrow()

    // The new key is bound to generation 1, not 0.
    await expect(
      unwrap(
        admin.wrappingKey.privateKey,
        wire(started.removerWrappedKey),
        memberWrapAAD(GROUP_ID, ADMIN_ID, 0),
      ),
    ).rejects.toThrow()
  })

  it('signs the rotation start naming the removed member, under the RotationStart context', async () => {
    const { admin, started } = await startedRotation()
    const sig = base64ToBytes(started.startSignature)
    const payload = rotationStartPayload(GROUP_ID, ADMIN_ID, SUBJECT_ID, 1)
    const pub = admin.signingKey.publicKey
    expect(ed25519.verify(pub, ed25519.SigningContext.RotationStart, payload, sig)).toBe(true)
    // Bound to the subject, the generation, the group and the context.
    for (const other of [
      rotationStartPayload(GROUP_ID, ADMIN_ID, 'someone-else', 1),
      rotationStartPayload(GROUP_ID, ADMIN_ID, SUBJECT_ID, 2),
      rotationStartPayload('other-group', ADMIN_ID, SUBJECT_ID, 1),
    ]) {
      expect(ed25519.verify(pub, ed25519.SigningContext.RotationStart, other, sig)).toBe(false)
    }
    expect(ed25519.verify(pub, ed25519.SigningContext.RoleGrant, payload, sig)).toBe(false)
  })

  it('mints a fresh key every time', async () => {
    const admin = await realUserKeys(ADMIN_ID, 'admin-password-rot-2')
    const created = await signGroupCreation(admin, GROUP_ID, new Uint8Array(32).fill(7))
    const own = wire(created.groupKeyWrapped)
    const a = await startGroupRotation(admin, GROUP_ID, own, 0, SUBJECT_ID)
    const b = await startGroupRotation(admin, GROUP_ID, own, 0, SUBJECT_ID)
    expect(a.removerWrappedKey.ciphertext).not.toBe(b.removerWrappedKey.ciphertext)
  })

  it('re-wraps the SAME new key to a member, readable only by them at that generation', async () => {
    const { admin, started } = await startedRotation()
    const carol = await realUserKeys(CAROL_ID, 'carol-password-rot')
    const newKey = await unwrap(
      admin.wrappingKey.privateKey,
      wire(started.removerWrappedKey),
      memberWrapAAD(GROUP_ID, ADMIN_ID, 1),
    )

    // A resumed run re-derives the key from the admin's OWN entry at gen 1.
    const wraps = await rewrapGroupKey(admin, GROUP_ID, wire(started.removerWrappedKey), 1, [
      { userId: CAROL_ID, x25519PublicKey: carol.wrappingKey.publicKey },
    ])
    expect(wraps).toHaveLength(1)
    const carolsKey = await unwrap(
      carol.wrappingKey.privateKey,
      wire(wraps[0]!.wrappedKey),
      memberWrapAAD(GROUP_ID, CAROL_ID, 1),
    )
    expect(carolsKey).toEqual(newKey)

    // Bound to carol's identity and the generation; not readable by the admin.
    await expect(
      unwrap(
        carol.wrappingKey.privateKey,
        wire(wraps[0]!.wrappedKey),
        memberWrapAAD(GROUP_ID, ADMIN_ID, 1),
      ),
    ).rejects.toThrow()
    await expect(
      unwrap(
        carol.wrappingKey.privateKey,
        wire(wraps[0]!.wrappedKey),
        memberWrapAAD(GROUP_ID, CAROL_ID, 0),
      ),
    ).rejects.toThrow()
    await expect(
      unwrap(
        admin.wrappingKey.privateKey,
        wire(wraps[0]!.wrappedKey),
        memberWrapAAD(GROUP_ID, CAROL_ID, 1),
      ),
    ).rejects.toThrow()
  })

  it('refuses to re-wrap to the caller or to a malformed key', async () => {
    const { admin, started } = await startedRotation()
    const own = wire(started.removerWrappedKey)
    await expect(
      rewrapGroupKey(admin, GROUP_ID, own, 1, [
        { userId: ADMIN_ID, x25519PublicKey: admin.wrappingKey.publicKey },
      ]),
    ).rejects.toThrow(/caller/)
    await expect(
      rewrapGroupKey(admin, GROUP_ID, own, 1, [
        { userId: CAROL_ID, x25519PublicKey: new Uint8Array(31) },
      ]),
    ).rejects.toThrow(/32 bytes/)
  })

  it('cannot re-wrap from an entry that is not at the stated generation', async () => {
    const { admin, started } = await startedRotation()
    const carol = await realUserKeys(CAROL_ID, 'carol-password-rot-2')
    await expect(
      rewrapGroupKey(admin, GROUP_ID, wire(started.removerWrappedKey), 0, [
        { userId: CAROL_ID, x25519PublicKey: carol.wrappingKey.publicKey },
      ]),
    ).rejects.toThrow()
  })
})

describe('signSuccessorDesignation and signSuccessorClaim', () => {
  const GROUP_ID = '44444444-4444-4444-8444-444444444444'
  const SUCCESSOR_ID = '55555555-5555-4555-8555-555555555555'
  const ADMIN_REF = 'GRANT#11111111-1111-4111-8111-111111111111#2026-09-01#aaaaaaaaaaaaaaaa'

  async function keysFor() {
    const signup = await generateSignupMaterial(USER_ID, 'successor-password', () => {})
    const { keys } = await completeLogin({
      password: 'successor-password',
      salt: signup.salt,
      argon2Params: signup.argon2Params,
      wrappedPrivateKeys: signup.wrappedPrivateKeys,
      userId: USER_ID,
      nonce: Buffer.from([6, 6, 6, 6]).toString('base64'),
    })
    return keys
  }

  it('signs a designation that binds each field, under the designation context only', async () => {
    const keys = await keysFor()
    const { designationSortKey, signature } = signSuccessorDesignation(
      keys,
      GROUP_ID,
      SUCCESSOR_ID,
      90,
      ADMIN_REF,
    )
    expect(designationSortKey.startsWith(`DESIGNATION#${USER_ID}#`)).toBe(true)
    const verifies = (
      ctx: (typeof ed25519.SigningContext)[keyof typeof ed25519.SigningContext],
      successor: string,
      period: number,
      ref: string,
      sortKey: string,
    ) =>
      ed25519.verify(
        keys.signingKey.publicKey,
        ctx,
        successorDesignationPayload(GROUP_ID, USER_ID, successor, period, sortKey, ref),
        base64ToBytes(signature),
      )
    const D = ed25519.SigningContext.SuccessorDesignation
    expect(verifies(D, SUCCESSOR_ID, 90, ADMIN_REF, designationSortKey)).toBe(true)
    expect(verifies(D, '', 90, ADMIN_REF, designationSortKey)).toBe(false)
    expect(verifies(D, SUCCESSOR_ID, 91, ADMIN_REF, designationSortKey)).toBe(false)
    expect(verifies(D, SUCCESSOR_ID, 90, 'GRANT#other', designationSortKey)).toBe(false)
    expect(verifies(D, SUCCESSOR_ID, 90, ADMIN_REF, `${designationSortKey}x`)).toBe(false)
    expect(
      verifies(ed25519.SigningContext.RoleGrant, SUCCESSOR_ID, 90, ADMIN_REF, designationSortKey),
    ).toBe(false)
  })

  it('signs the revocation form with an empty successor', async () => {
    const keys = await keysFor()
    const { designationSortKey, signature } = signSuccessorDesignation(
      keys,
      GROUP_ID,
      '',
      90,
      ADMIN_REF,
    )
    expect(
      ed25519.verify(
        keys.signingKey.publicKey,
        ed25519.SigningContext.SuccessorDesignation,
        successorDesignationPayload(GROUP_ID, USER_ID, '', 90, designationSortKey, ADMIN_REF),
        base64ToBytes(signature),
      ),
    ).toBe(true)
  })

  it('refuses a non-integer period rather than signing it', async () => {
    const keys = await keysFor()
    expect(() => signSuccessorDesignation(keys, GROUP_ID, SUCCESSOR_ID, 90.5, ADMIN_REF)).toThrow(
      /integer/,
    )
  })

  it('signs a claim that binds the designation and its own address, under the claim context only', async () => {
    const keys = await keysFor()
    const DESIGNATION = `DESIGNATION#${SUCCESSOR_ID}#2026-06-01#bbbbbbbbbbbbbbbb`
    const { claimSortKey, signature } = signSuccessorClaim(keys, GROUP_ID, DESIGNATION)
    expect(claimSortKey.startsWith(`GRANT#${USER_ID}#`)).toBe(true)
    const verifies = (
      ctx: (typeof ed25519.SigningContext)[keyof typeof ed25519.SigningContext],
      designation: string,
      sortKey: string,
    ) =>
      ed25519.verify(
        keys.signingKey.publicKey,
        ctx,
        successorClaimPayload(GROUP_ID, USER_ID, designation, sortKey),
        base64ToBytes(signature),
      )
    const C = ed25519.SigningContext.SuccessorClaim
    expect(verifies(C, DESIGNATION, claimSortKey)).toBe(true)
    expect(verifies(C, `${DESIGNATION}x`, claimSortKey)).toBe(false)
    expect(verifies(C, DESIGNATION, `${claimSortKey}x`)).toBe(false)
    expect(verifies(ed25519.SigningContext.RoleGrant, DESIGNATION, claimSortKey)).toBe(false)
  })
})
