import { describe, expect, it } from 'vitest'
import { base64ToBytes, bytesToBase64 } from './base64.js'
import { completeLogin, startSelfRekey, type LiveKeys } from './credential-material.js'
import * as ed25519 from './ed25519.js'
import { memberWrapAAD } from './group.js'
import { handoffWrapAAD, keyRotationPayload, rosterDigest, rosterEntryId } from './key-rotation.js'
import {
  beginKeyRotation,
  commitKeyRotation,
  MAX_ROSTER_ENTRIES,
  RosterTooLargeError,
  RotationState,
  signKeyRotation,
  wrapHandoff,
} from './rotation-material.js'
import { generateWrappingKey, unwrap, wrap } from './x25519.js'

const USER = '11111111-2222-4333-8444-555555555555'
const GROUP = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'

function liveKeys(): LiveKeys {
  return {
    userId: USER,
    signingKey: ed25519.generateSigningKey(),
    wrappingKey: generateWrappingKey(),
  }
}

async function ownEntry(keys: LiveKeys, groupKey: Uint8Array, generation: number) {
  const w = await wrap(keys.wrappingKey.publicKey, groupKey, memberWrapAAD(GROUP, USER, generation))
  return {
    ephemeralPub: bytesToBase64(w.ephemeralPub),
    nonce: bytesToBase64(w.nonce),
    ciphertext: bytesToBase64(w.ciphertext),
  }
}

describe('beginKeyRotation', () => {
  it('mints keys that are not the live ones and returns only public halves', () => {
    const keys = liveKeys()
    const { pending, newSigningPublicKey, newWrappingPublicKey } = beginKeyRotation(keys)
    expect(base64ToBytes(newSigningPublicKey)).toEqual(pending.signingKey.publicKey)
    expect(base64ToBytes(newWrappingPublicKey)).toEqual(pending.wrappingKey.publicKey)
    expect(pending.signingKey.publicKey).not.toEqual(keys.signingKey.publicKey)
    expect(pending.wrappingKey.publicKey).not.toEqual(keys.wrappingKey.publicKey)
  })
})

describe('wrapHandoff', () => {
  it('wraps the group key to the NEW key, readable only there and only under its AAD', async () => {
    const keys = liveKeys()
    const groupKey = crypto.getRandomValues(new Uint8Array(32))
    const { pending } = beginKeyRotation(keys)
    const out = await wrapHandoff(keys, pending, {
      groupId: GROUP,
      ownWrappedGroupKey: await ownEntry(keys, groupKey, 3),
      generation: 3,
    })
    expect(out.generation).toBe(3)
    expect(base64ToBytes(out.newWrappingPublicKey)).toEqual(pending.wrappingKey.publicKey)
    const w = {
      ephemeralPub: base64ToBytes(out.wrappedGroupKey.ephemeralPub),
      nonce: base64ToBytes(out.wrappedGroupKey.nonce),
      ciphertext: base64ToBytes(out.wrappedGroupKey.ciphertext),
    }
    const aad = handoffWrapAAD(USER, GROUP, 3, pending.wrappingKey.publicKey)
    expect(await unwrap(pending.wrappingKey.privateKey, w, aad)).toEqual(groupKey)
    // The old key cannot open it, and a row for another group or generation fails.
    await expect(unwrap(keys.wrappingKey.privateKey, w, aad)).rejects.toThrow()
    await expect(
      unwrap(
        pending.wrappingKey.privateKey,
        w,
        handoffWrapAAD(USER, GROUP, 4, pending.wrappingKey.publicKey),
      ),
    ).rejects.toThrow()
    await expect(
      unwrap(
        pending.wrappingKey.privateKey,
        w,
        handoffWrapAAD(
          USER,
          'cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee',
          3,
          pending.wrappingKey.publicKey,
        ),
      ),
    ).rejects.toThrow()
  })

  it('is what the self re-key opens: the row written before the rotation starts the one after it', async () => {
    const oldKeys = liveKeys()
    const groupKey = crypto.getRandomValues(new Uint8Array(32))
    const { pending } = beginKeyRotation(oldKeys)
    const out = await wrapHandoff(oldKeys, pending, {
      groupId: GROUP,
      ownWrappedGroupKey: await ownEntry(oldKeys, groupKey, 3),
      generation: 3,
    })
    // After the rotation commits, the account holds the pending keys.
    const newKeys: LiveKeys = {
      userId: USER,
      signingKey: pending.signingKey,
      wrappingKey: pending.wrappingKey,
    }
    const started = await startSelfRekey(newKeys, GROUP, out.generation, {
      ephemeralPub: base64ToBytes(out.wrappedGroupKey.ephemeralPub),
      nonce: base64ToBytes(out.wrappedGroupKey.nonce),
      ciphertext: base64ToBytes(out.wrappedGroupKey.ciphertext),
    })
    expect(started.generation).toBe(4)
    // The old keys cannot start it: the row is not wrapped to them.
    await expect(
      startSelfRekey(oldKeys, GROUP, out.generation, {
        ephemeralPub: base64ToBytes(out.wrappedGroupKey.ephemeralPub),
        nonce: base64ToBytes(out.wrappedGroupKey.nonce),
        ciphertext: base64ToBytes(out.wrappedGroupKey.ciphertext),
      }),
    ).rejects.toThrow()
  })

  it('refuses an entry that is not at the generation named', async () => {
    const keys = liveKeys()
    const { pending } = beginKeyRotation(keys)
    await expect(
      wrapHandoff(keys, pending, {
        groupId: GROUP,
        ownWrappedGroupKey: await ownEntry(keys, crypto.getRandomValues(new Uint8Array(32)), 2),
        generation: 3,
      }),
    ).rejects.toThrow()
  })
})

describe('signKeyRotation', () => {
  const roster = [
    rosterEntryId(`PIN#${GROUP}`, new Uint8Array(64).fill(1)),
    rosterEntryId(`VERIFIED#${GROUP}`, new Uint8Array(64).fill(2)),
  ].map(bytesToBase64)

  it('signs one payload under both keys and wraps the NEW keys under the new password', async () => {
    const keys = liveKeys()
    const { pending } = beginKeyRotation(keys)
    const steps: number[] = []
    const out = await signKeyRotation(
      keys,
      pending,
      { newPassword: 'a new password', expectedKeyEpoch: 2, roster },
      (s) => steps.push(s.step),
      new Date('2026-10-22T23:59:00Z'),
    )
    expect(out.signedDay).toBe('2026-10-22')
    const payload = keyRotationPayload(
      USER,
      keys.signingKey.publicKey,
      keys.wrappingKey.publicKey,
      pending.signingKey.publicKey,
      pending.wrappingKey.publicKey,
      '2026-10-22',
      2,
      rosterDigest(roster.map(base64ToBytes)),
    )
    const ctx = ed25519.SigningContext.KeyRotation
    expect(
      ed25519.verify(keys.signingKey.publicKey, ctx, payload, base64ToBytes(out.oldSignature)),
    ).toBe(true)
    expect(
      ed25519.verify(pending.signingKey.publicKey, ctx, payload, base64ToBytes(out.newSignature)),
    ).toBe(true)
    // Each signature is under its own key only.
    expect(
      ed25519.verify(pending.signingKey.publicKey, ctx, payload, base64ToBytes(out.oldSignature)),
    ).toBe(false)
    expect(
      ed25519.verify(keys.signingKey.publicKey, ctx, payload, base64ToBytes(out.newSignature)),
    ).toBe(false)
    expect(out.roster).toEqual(roster)

    // The password wrap opens to the NEW keys.
    const login = await completeLogin({
      password: 'a new password',
      salt: out.credentials.salt,
      argon2Params: out.credentials.argon2Params,
      wrappedPrivateKeys: out.credentials.wrappedPrivateKeys,
      userId: USER,
      nonce: bytesToBase64(new Uint8Array(32)),
    })
    expect(login.keys.signingKey.publicKey).toEqual(pending.signingKey.publicKey)
    expect(login.keys.wrappingKey.publicKey).toEqual(pending.wrappingKey.publicKey)
    expect(out.credentials.recoveryCode).toMatch(/\S/)
    expect(steps).toEqual([1, 2, 3])
  }, 60_000)

  it('signs a different payload for a different epoch or roster', async () => {
    const keys = liveKeys()
    const { pending } = beginKeyRotation(keys)
    const now = new Date('2026-10-22T00:00:00Z')
    const a = await signKeyRotation(
      keys,
      pending,
      { newPassword: 'pw', expectedKeyEpoch: 0, roster },
      () => {},
      now,
    )
    const b = await signKeyRotation(
      keys,
      pending,
      { newPassword: 'pw', expectedKeyEpoch: 1, roster },
      () => {},
      now,
    )
    const c = await signKeyRotation(
      keys,
      pending,
      { newPassword: 'pw', expectedKeyEpoch: 0, roster: [] },
      () => {},
      now,
    )
    expect(a.oldSignature).not.toBe(b.oldSignature)
    expect(a.oldSignature).not.toBe(c.oldSignature)
  }, 60_000)

  it('refuses an oversized roster and a malformed entry before doing any work', async () => {
    const keys = liveKeys()
    const { pending } = beginKeyRotation(keys)
    const entry = bytesToBase64(new Uint8Array(16))
    await expect(
      signKeyRotation(
        keys,
        pending,
        {
          newPassword: 'pw',
          expectedKeyEpoch: 0,
          roster: Array(MAX_ROSTER_ENTRIES + 1).fill(entry),
        },
        () => {},
      ),
    ).rejects.toBeInstanceOf(RosterTooLargeError)
    await expect(
      signKeyRotation(
        keys,
        pending,
        { newPassword: 'pw', expectedKeyEpoch: 0, roster: [bytesToBase64(new Uint8Array(15))] },
        () => {},
      ),
    ).rejects.toThrow('16 bytes')
  })
})

describe('commitKeyRotation', () => {
  it('returns the pending keys as the live keys for the same account', () => {
    const keys = liveKeys()
    const { pending } = beginKeyRotation(keys)
    const next = commitKeyRotation(pending)
    expect(next.userId).toBe(USER)
    expect(next.signingKey).toBe(pending.signingKey)
    expect(next.wrappingKey).toBe(pending.wrappingKey)
  })
})

describe('RotationState', () => {
  it('refuses pins and verifications only while a rotation is in flight', () => {
    const state = new RotationState()
    expect(() => state.assertIdle('pin a key')).not.toThrow()
    state.begin(beginKeyRotation(liveKeys()).pending)
    expect(() => state.assertIdle('pin a key')).toThrow('rotation is in progress')
    state.clear()
    expect(() => state.assertIdle('pin a key')).not.toThrow()
  })

  it('serves the pending rotation to its own account only', () => {
    const state = new RotationState()
    expect(() => state.require(USER)).toThrow('no key rotation')
    const { pending } = beginKeyRotation(liveKeys())
    state.begin(pending)
    expect(state.require(USER)).toBe(pending)
    expect(() => state.require('someone-else')).toThrow('no key rotation')
  })

  it('commit returns the new keys, clears the state and lets pins resume', () => {
    const state = new RotationState()
    const { pending } = beginKeyRotation(liveKeys())
    state.begin(pending)
    const next = state.commit(USER)
    expect(next.wrappingKey).toBe(pending.wrappingKey)
    expect(() => state.assertIdle('pin a key')).not.toThrow()
    expect(() => state.require(USER)).toThrow()
  })

  it('a restart replaces the earlier attempt', () => {
    const state = new RotationState()
    const first = beginKeyRotation(liveKeys()).pending
    const second = beginKeyRotation(liveKeys()).pending
    state.begin(first)
    state.begin(second)
    expect(state.require(USER)).toBe(second)
  })
})
