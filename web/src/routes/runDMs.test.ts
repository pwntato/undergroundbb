import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import { DMExistsError, type IncomingDM } from '@/lib/api/dms'
import type { UserProjection } from '@/lib/api/users'
import { base64ToBytes, bytesToBase64 } from '@/lib/crypto/base64'
import * as ed25519 from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { admissionPayload } from '@/lib/crypto/group'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import { generateWrappingKey } from '@/lib/crypto/x25519'
import { CLOCK_SKEW_MESSAGE } from './replyState'
import {
  acceptDMFailureMessage,
  prepareAcceptDM,
  prepareStartDM,
  runAcceptDM,
  runDeclineDM,
  runStartDM,
  shouldReloadAfterAccept,
  startDMFailureMessage,
  type AcceptDMDeps,
  type DMMaterial,
  type StartDMDeps,
} from './runDMs'

const GROUP = '11111111-1111-4111-8111-111111111111'
const ME = '22222222-2222-4222-8222-222222222222'
const OTHER = '33333333-3333-4333-8333-333333333333'
const REQUEST_ID = '44444444-4444-4444-8444-444444444444'
const GRANT_REF = 'GRANT#root'
const DAY = '2026-11-09'
const NOW = Date.parse(`${DAY}T12:00:00Z`)
const MATERIAL: DMMaterial = {
  groupId: GROUP,
  groupKeyB64: bytesToBase64(new Uint8Array(32).fill(7)),
  requestId: REQUEST_ID,
}

interface Person {
  readonly signing: ed25519.SigningKey
  readonly edB64: string
  readonly xB64: string
  readonly xRaw: Uint8Array
}
function person(): Person {
  const signing = ed25519.generateSigningKey()
  const wrapping = generateWrappingKey()
  return {
    signing,
    edB64: bytesToBase64(signing.publicKey),
    xB64: bytesToBase64(wrapping.publicKey),
    xRaw: wrapping.publicKey,
  }
}
const prints = (p: Person): string => fingerprint(p.signing.publicKey, p.xRaw)

const me = person()
const mePub = me.edB64

function served(p: Person, userId: string, over: Partial<UserProjection> = {}): UserProjection {
  return {
    userId,
    username: 'someone',
    signingPublicKey: p.edB64,
    wrappingPublicKey: p.xB64,
    supersededSigningKeys: [],
    keyEpoch: 0,
    ...over,
  }
}

/** A pin I saved of `p` (as user `userId`). */
function pinOf(p: Person, userId: string, keyEpoch = 0): PinRecord {
  const signedDay = '2026-11-01'
  const sig = ed25519.sign(
    me.signing,
    ed25519.SigningContext.Pin,
    pinPayload(
      ME,
      userId,
      me.signing.publicKey,
      p.xRaw,
      [p.signing.publicKey],
      keyEpoch,
      signedDay,
    ),
  )
  return {
    pinnedUserId: userId,
    signingPublicKeys: [p.edB64],
    wrappingPublicKey: p.xB64,
    pinnerSigningPublicKey: mePub,
    signature: bytesToBase64(sig),
    keyEpoch,
    signedDay,
  }
}

const SIGNED = {
  trustAnchorSignature: 'anchor-sig',
  rootGrantSortKey: GRANT_REF,
  rootGrantSignature: 'grant-sig',
  groupKeyWrapped: { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' },
}
const WRAPPED = { ephemeralPub: 'we', nonce: 'wn', ciphertext: 'wc' }

// ---------------------------------------------------------------------------------------------
// The sender
// ---------------------------------------------------------------------------------------------

function startDeps(
  other: Person,
  over: Partial<StartDMDeps> & {
    served?: UserProjection | undefined
    pins?: PinRecord[]
  } = {},
) {
  const { served: servedOverride, pins, ...rest } = over
  const projection = 'served' in over ? servedOverride : served(other, OTHER)
  const deps = {
    selfUserId: ME,
    now: () => NOW,
    ownSigningKey: vi.fn(async () => mePub),
    getUsers: vi.fn(async () => new Map(projection ? [[OTHER, projection]] : [])),
    listPins: vi.fn(async () => pins ?? []),
    pinKeys: vi.fn(async () => undefined),
    signGroupCreation: vi.fn(async () => SIGNED),
    rewrapCrypto: vi.fn(async () => ({ wraps: [{ userId: OTHER, wrappedKey: WRAPPED }] })),
    signReadmission: vi.fn(async (req: { inviterGrantRef: string; day: string }) => ({
      inviterGrantRef: req.inviterGrantRef,
      day: req.day,
      signature: 'admission-sig',
    })),
    createDM: vi.fn(async () => ({ groupId: GROUP, rootGrantSortKey: GRANT_REF })),
    ...rest,
  }
  return deps as typeof deps & StartDMDeps
}

describe('prepareStartDM', () => {
  it('shows the fingerprint of the keys the server serves, as trust on first use', async () => {
    const other = person()
    const out = await prepareStartDM(startDeps(other), OTHER)
    expect(out).toEqual({ ok: true, fingerprint: prints(other), firstSight: true })
  })

  it('says it is not first sight when the keys match the saved copy', async () => {
    const other = person()
    const out = await prepareStartDM(startDeps(other, { pins: [pinOf(other, OTHER)] }), OTHER)
    expect(out).toEqual({ ok: true, fingerprint: prints(other), firstSight: false })
  })

  it('blocks keys that differ from the saved copy', async () => {
    const saved = person()
    const out = await prepareStartDM(startDeps(person(), { pins: [pinOf(saved, OTHER)] }), OTHER)
    expect(out).toEqual({ ok: false, kind: 'pinMismatch' })
  })

  it.each([
    ['a rollback of their key epoch', (p: Person) => ({ pin: pinOf(p, OTHER, 2), epoch: 1 })],
    [
      'a saved copy whose signature does not verify',
      (p: Person) => ({
        pin: { ...pinOf(p, OTHER), signature: bytesToBase64(new Uint8Array(64)) },
        epoch: 0,
      }),
    ],
  ])('blocks %s, not only a plain key change', async (_name, make) => {
    const other = person()
    const { pin, epoch } = make(other)
    const deps = startDeps(other, {
      served: served(other, OTHER, { keyEpoch: epoch }),
      pins: [pin],
    })
    expect(await prepareStartDM(deps, OTHER)).toEqual({ ok: false, kind: 'pinMismatch' })
    expect(await runStartDM(deps, OTHER, prints(other), MATERIAL, 30)).toEqual({
      ok: false,
      kind: 'pinMismatch',
    })
    expect(deps.createDM).not.toHaveBeenCalled()
  })

  it('refuses to message yourself, without asking the server', async () => {
    const deps = startDeps(person())
    expect(await prepareStartDM(deps, ME)).toEqual({ ok: false, kind: 'self' })
    expect(deps.getUsers).not.toHaveBeenCalled()
  })

  it('reports an unknown and a deleted account', async () => {
    expect(await prepareStartDM(startDeps(person(), { served: undefined }), OTHER)).toEqual({
      ok: false,
      kind: 'gone',
    })
    const other = person()
    expect(
      await prepareStartDM(
        startDeps(other, { served: served(other, OTHER, { deleted: true }) }),
        OTHER,
      ),
    ).toEqual({ ok: false, kind: 'deleted' })
  })

  it('does not show a fingerprint when their keys could not be read', async () => {
    const out = await prepareStartDM(
      startDeps(person(), {
        getUsers: vi.fn(async (_ids: readonly string[], onError?: (e: unknown) => void) => {
          onError?.(new Error('offline'))
          return new Map<string, UserProjection>()
        }),
      }),
      OTHER,
    )
    expect(out).toMatchObject({ ok: false, kind: 'unchecked' })
  })
})

describe('runStartDM', () => {
  it('wraps to and signs over exactly the keys whose fingerprint was confirmed, then sends', async () => {
    const other = person()
    const deps = startDeps(other)
    const out = await runStartDM(deps, OTHER, prints(other), MATERIAL, 45)
    expect(out).toEqual({ ok: true, groupId: GROUP })

    expect(deps.signGroupCreation).toHaveBeenCalledWith({
      userId: ME,
      groupId: GROUP,
      groupKey: MATERIAL.groupKeyB64,
    })
    expect(deps.rewrapCrypto).toHaveBeenCalledWith({
      userId: ME,
      groupId: GROUP,
      ownWrappedGroupKey: SIGNED.groupKeyWrapped,
      ownGeneration: 0,
      recipients: [{ userId: OTHER, x25519PublicKey: other.xB64 }],
    })
    expect(deps.signReadmission).toHaveBeenCalledWith({
      userId: ME,
      groupId: GROUP,
      subjectUserId: OTHER,
      subjectEd25519PublicKey: other.edB64,
      subjectX25519PublicKey: other.xB64,
      inviteId: REQUEST_ID,
      inviterGrantRef: GRANT_REF,
      day: DAY,
      generation: 0,
    })
    expect(deps.createDM).toHaveBeenCalledWith({
      groupId: GROUP,
      visibility: 'private',
      revocationMode: 'open',
      expirationDays: 45,
      groupKeyWrapped: SIGNED.groupKeyWrapped,
      trustAnchorSignature: 'anchor-sig',
      rootGrantSortKey: GRANT_REF,
      rootGrantSignature: 'grant-sig',
      dm: {
        recipientUserId: OTHER,
        requestId: REQUEST_ID,
        wrappedGroupKey: WRAPPED,
        admission: { day: DAY, signature: 'admission-sig' },
      },
    })
  })

  it('saves their keys on first sight and only then', async () => {
    const other = person()
    const first = startDeps(other)
    await runStartDM(first, OTHER, prints(other), MATERIAL, 30)
    expect(first.pinKeys).toHaveBeenCalledWith(OTHER, [other.edB64], other.xB64, 0)

    const again = startDeps(other, { pins: [pinOf(other, OTHER)] })
    await runStartDM(again, OTHER, prints(other), MATERIAL, 30)
    expect(again.pinKeys).not.toHaveBeenCalled()
  })

  it('sends nothing if the keys now are not the ones whose fingerprint was confirmed', async () => {
    const shown = person()
    const swapped = person()
    const deps = startDeps(swapped)
    const out = await runStartDM(deps, OTHER, prints(shown), MATERIAL, 30)
    expect(out).toEqual({ ok: false, kind: 'keysChanged' })
    expect(deps.signGroupCreation).not.toHaveBeenCalled()
    expect(deps.rewrapCrypto).not.toHaveBeenCalled()
    expect(deps.signReadmission).not.toHaveBeenCalled()
    expect(deps.createDM).not.toHaveBeenCalled()
    expect(deps.pinKeys).not.toHaveBeenCalled()
  })

  it('sends nothing, and signs nothing, when only the wrapping key changed', async () => {
    const shown = person()
    const sameSigning = { ...shown, xB64: bytesToBase64(generateWrappingKey().publicKey) }
    const deps = startDeps(shown, { served: served(sameSigning, OTHER) })
    const out = await runStartDM(deps, OTHER, prints(shown), MATERIAL, 30)
    expect(out).toEqual({ ok: false, kind: 'keysChanged' })
    expect(deps.createDM).not.toHaveBeenCalled()
  })

  it('blocks at send time too when the keys no longer match the saved copy', async () => {
    const saved = person()
    const now = person()
    const deps = startDeps(now, { pins: [pinOf(saved, OTHER)] })
    const out = await runStartDM(deps, OTHER, prints(now), MATERIAL, 30)
    expect(out).toEqual({ ok: false, kind: 'pinMismatch' })
    expect(deps.signGroupCreation).not.toHaveBeenCalled()
  })

  it('does not go on if their keys could not be saved', async () => {
    const other = person()
    const deps = startDeps(other, {
      pinKeys: vi.fn(async () => {
        throw new Error('disk')
      }),
    })
    const out = await runStartDM(deps, OTHER, prints(other), MATERIAL, 30)
    expect(out).toMatchObject({ ok: false, kind: 'unchecked' })
    expect(deps.createDM).not.toHaveBeenCalled()
  })

  it('asks for the password when the tab has no keys, for each of the three worker steps', async () => {
    const cold = new Error('no live keys cached')
    for (const step of ['signGroupCreation', 'rewrapCrypto', 'signReadmission'] as const) {
      const other = person()
      const deps = startDeps(other, {
        [step]: vi.fn(async () => {
          throw cold
        }),
      })
      expect(await runStartDM(deps, OTHER, prints(other), MATERIAL, 30)).toEqual({
        ok: false,
        kind: 'coldKeys',
      })
      expect(deps.createDM).not.toHaveBeenCalled()
    }
  })

  it('does not send when the worker returns no wrap for them', async () => {
    const other = person()
    const deps = startDeps(other, { rewrapCrypto: vi.fn(async () => ({ wraps: [] })) })
    expect(await runStartDM(deps, OTHER, prints(other), MATERIAL, 30)).toMatchObject({
      ok: false,
      kind: 'rejected',
    })
    expect(deps.createDM).not.toHaveBeenCalled()
  })

  describe('what the server says', () => {
    async function sendWith(error: unknown) {
      const other = person()
      const deps = startDeps(other, {
        createDM: vi.fn(async () => {
          throw error
        }),
      })
      return runStartDM(deps, OTHER, prints(other), MATERIAL, 30)
    }

    it('goes to the existing conversation on dm_exists', async () => {
      const existing = '55555555-5555-4555-8555-555555555555'
      expect(await sendWith(new DMExistsError('already', existing))).toEqual({
        ok: false,
        kind: 'exists',
        groupId: existing,
      })
    })

    it('treats dm_exists naming THIS group as the earlier send having landed', async () => {
      expect(await sendWith(new DMExistsError('already', GROUP))).toEqual({
        ok: true,
        groupId: GROUP,
      })
    })

    it.each([
      [409, 'dm_cooling_off', 'coolingOff'],
      [429, 'too_many_pending_dms', 'tooManyPending'],
      [400, 'bad_signature', 'recipientKeysChanged'],
      [409, 'dm_conflict', 'conflict'],
      [404, 'recipient_not_found', 'gone'],
      [410, 'recipient_deleted', 'deleted'],
      [410, 'account_deleted', 'accountDeleted'],
    ] as const)('maps %s %s to %s', async (status, code, kind) => {
      expect(await sendWith(new ApiError(status, 'server words', code))).toMatchObject({
        ok: false,
        kind,
      })
    })

    it('keeps the server wording of a cool-off, which names the day', async () => {
      const out = await sendWith(
        new ApiError(
          409,
          'this person declined; you can try again after 2026-11-16',
          'dm_cooling_off',
        ),
      )
      expect(out).toMatchObject({ ok: false })
      if (!out.ok) {
        expect(startDMFailureMessage(out)).toBe(
          'this person declined; you can try again after 2026-11-16',
        )
      }
    })

    it('names the clock on clock_skew', async () => {
      const out = await sendWith(new ApiError(400, 'skew', 'clock_skew'))
      expect(out).toMatchObject({ ok: false, kind: 'rejected' })
      if (!out.ok) expect(startDMFailureMessage(out)).toBe(CLOCK_SKEW_MESSAGE)
    })

    it('sends the person to log in on 401, and shows other refusals as they are', async () => {
      expect(await sendWith(new ApiError(401, 'no'))).toMatchObject({ kind: 'authRequired' })
      expect(await sendWith(new ApiError(400, 'bad shape'))).toMatchObject({
        kind: 'rejected',
        message: 'bad shape',
      })
    })

    it('does not claim to know whether a lost or failed response landed', async () => {
      expect(await sendWith(new TypeError('network'))).toMatchObject({ kind: 'ambiguous' })
      expect(await sendWith(new ApiError(500, 'oops'))).toMatchObject({ kind: 'ambiguous' })
    })
  })

  it('has a message for every failure it can return', () => {
    const kinds = [
      { kind: 'pinMismatch' },
      { kind: 'keysChanged' },
      { kind: 'gone' },
      { kind: 'deleted' },
      { kind: 'self' },
      { kind: 'exists', groupId: GROUP },
      { kind: 'tooManyPending' },
      { kind: 'recipientKeysChanged' },
      { kind: 'conflict' },
      { kind: 'authRequired' },
      { kind: 'coldKeys' },
      { kind: 'accountDeleted' },
      { kind: 'ambiguous' },
    ] as const
    for (const k of kinds) {
      expect(startDMFailureMessage({ ok: false, ...k }).length).toBeGreaterThan(10)
    }
  })
})

// ---------------------------------------------------------------------------------------------
// The recipient
// ---------------------------------------------------------------------------------------------

/** A DM from `sender` to ME with a genuine admission signature over ME's keys. */
function incoming(
  sender: Person,
  over: Partial<IncomingDM> & { signWith?: ed25519.SigningKey } = {},
): IncomingDM {
  const { signWith, ...rest } = over
  const base = {
    groupId: GROUP,
    senderUserId: OTHER,
    requestId: REQUEST_ID,
    recipientEd25519PublicKey: me.edB64,
    recipientX25519PublicKey: me.xB64,
    wrappedGroupKey: WRAPPED,
    admissionDay: DAY,
    admissionGrantRef: GRANT_REF,
    ...rest,
  }
  const payload = admissionPayload(
    GROUP,
    OTHER,
    ME,
    base64ToBytes(base.recipientEd25519PublicKey),
    base64ToBytes(base.recipientX25519PublicKey),
    base.requestId,
    base.admissionGrantRef,
    base.admissionDay,
    0,
  )
  const sig = ed25519.sign(signWith ?? sender.signing, ed25519.SigningContext.Admission, payload)
  return { admissionSignature: bytesToBase64(sig), ...base } as IncomingDM
}

function acceptDeps(
  sender: Person,
  over: Partial<AcceptDMDeps> & {
    served?: UserProjection | undefined
    pins?: PinRecord[]
  } = {},
) {
  const { served: servedOverride, pins, ...rest } = over
  const projection = 'served' in over ? servedOverride : served(sender, OTHER)
  const deps = {
    selfUserId: ME,
    ownSigningKey: vi.fn(async () => mePub),
    ownFingerprint: vi.fn(async () => prints(me)),
    getUsers: vi.fn(async () => new Map(projection ? [[OTHER, projection]] : [])),
    listPins: vi.fn(async () => pins ?? []),
    pinKeys: vi.fn(async () => undefined),
    acceptDM: vi.fn(async () => undefined),
    declineDM: vi.fn(async () => undefined),
    ...rest,
  }
  return deps as typeof deps & AcceptDMDeps
}

describe('prepareAcceptDM', () => {
  it("shows the sender's fingerprint, as trust on first use", async () => {
    const sender = person()
    expect(await prepareAcceptDM(acceptDeps(sender), incoming(sender))).toEqual({
      ok: true,
      fingerprint: prints(sender),
      firstSight: true,
    })
  })

  it('says it is not first sight when the sender matches the saved copy', async () => {
    const sender = person()
    const out = await prepareAcceptDM(
      acceptDeps(sender, { pins: [pinOf(sender, OTHER)] }),
      incoming(sender),
    )
    expect(out).toEqual({ ok: true, fingerprint: prints(sender), firstSight: false })
  })

  it('refuses an admission signed by someone other than the sender', async () => {
    const sender = person()
    const impostor = person()
    const out = await prepareAcceptDM(
      acceptDeps(sender),
      incoming(sender, { signWith: impostor.signing }),
    )
    expect(out).toEqual({ ok: false, kind: 'badAdmission' })
  })

  it.each([
    ['groupId', { groupId: '66666666-6666-4666-8666-666666666666' }],
    ['requestId', { requestId: '77777777-7777-4777-8777-777777777777' }],
    ['admissionGrantRef', { admissionGrantRef: 'GRANT#other' }],
    ['admissionDay', { admissionDay: '2026-11-08' }],
  ] as const)('refuses an admission whose %s was changed after signing', async (_name, change) => {
    const sender = person()
    const good = incoming(sender)
    const out = await prepareAcceptDM(acceptDeps(sender), { ...good, ...change })
    expect(out).toEqual({ ok: false, kind: 'badAdmission' })
  })

  it('refuses a DM whose signature was made for another recipient', async () => {
    const sender = person()
    const good = incoming(sender)
    const forAnother = ed25519.sign(
      sender.signing,
      ed25519.SigningContext.Admission,
      admissionPayload(
        GROUP,
        OTHER,
        '88888888-8888-4888-8888-888888888888',
        me.signing.publicKey,
        me.xRaw,
        REQUEST_ID,
        GRANT_REF,
        DAY,
        0,
      ),
    )
    const out = await prepareAcceptDM(acceptDeps(sender), {
      ...good,
      admissionSignature: bytesToBase64(forAnother),
    })
    expect(out).toEqual({ ok: false, kind: 'badAdmission' })
  })

  it('refuses a DM made for keys that are not this device’s, even when validly signed', async () => {
    const sender = person()
    const stranger = person()
    const dm = incoming(sender, {
      recipientEd25519PublicKey: stranger.edB64,
      recipientX25519PublicKey: stranger.xB64,
    })
    expect(await prepareAcceptDM(acceptDeps(sender), dm)).toEqual({
      ok: false,
      kind: 'notYourKeys',
    })
  })

  it('refuses when only the X25519 key differs from this device’s', async () => {
    const sender = person()
    const dm = incoming(sender, {
      recipientX25519PublicKey: bytesToBase64(generateWrappingKey().publicKey),
    })
    expect(await prepareAcceptDM(acceptDeps(sender), dm)).toEqual({
      ok: false,
      kind: 'notYourKeys',
    })
  })

  it('asks for the password when this tab cannot read its own fingerprint', async () => {
    const sender = person()
    const deps = acceptDeps(sender, {
      ownFingerprint: vi.fn(async () => {
        throw new Error('no live keys cached')
      }),
    })
    expect(await prepareAcceptDM(deps, incoming(sender))).toEqual({ ok: false, kind: 'coldKeys' })
  })

  it('blocks a sender whose keys differ from the saved copy', async () => {
    const saved = person()
    const now = person()
    const out = await prepareAcceptDM(
      acceptDeps(now, { pins: [pinOf(saved, OTHER)] }),
      incoming(now),
    )
    expect(out).toEqual({ ok: false, kind: 'pinMismatch' })
  })

  it.each([
    ['a rollback of their key epoch', (p: Person) => ({ pin: pinOf(p, OTHER, 2), epoch: 1 })],
    [
      'a saved copy whose signature does not verify',
      (p: Person) => ({
        pin: { ...pinOf(p, OTHER), signature: bytesToBase64(new Uint8Array(64)) },
        epoch: 0,
      }),
    ],
  ])('blocks a sender with %s, not only a plain key change', async (_name, make) => {
    const sender = person()
    const { pin, epoch } = make(sender)
    const deps = acceptDeps(sender, {
      served: served(sender, OTHER, { keyEpoch: epoch }),
      pins: [pin],
    })
    expect(await prepareAcceptDM(deps, incoming(sender))).toEqual({
      ok: false,
      kind: 'pinMismatch',
    })
    expect(await runAcceptDM(deps, incoming(sender), prints(sender))).toEqual({
      ok: false,
      kind: 'pinMismatch',
    })
    expect(deps.acceptDM).not.toHaveBeenCalled()
  })

  it('accepts an admission signed with a key the sender has since replaced', async () => {
    const old = person()
    const current = person()
    const projection = served(current, OTHER, {
      keyEpoch: 1,
      supersededSigningKeys: [{ publicKey: old.edB64, from: '2026-01-01', until: '2026-11-01' }],
    })
    const out = await prepareAcceptDM(acceptDeps(current, { served: projection }), incoming(old))
    expect(out).toMatchObject({ ok: true, fingerprint: prints(current) })
  })

  it('reports a sender who is gone or deleted', async () => {
    const sender = person()
    expect(
      await prepareAcceptDM(acceptDeps(sender, { served: undefined }), incoming(sender)),
    ).toEqual({
      ok: false,
      kind: 'gone',
    })
    expect(
      await prepareAcceptDM(
        acceptDeps(sender, { served: served(sender, OTHER, { deleted: true }) }),
        incoming(sender),
      ),
    ).toEqual({ ok: false, kind: 'deleted' })
  })

  it('refuses a malformed signature without throwing', async () => {
    const sender = person()
    const dm = { ...incoming(sender), admissionSignature: '!!!not base64!!!' }
    expect(await prepareAcceptDM(acceptDeps(sender), dm)).toEqual({
      ok: false,
      kind: 'badAdmission',
    })
  })
})

describe('runAcceptDM', () => {
  it('accepts exactly the DM that was checked, after the fingerprint was confirmed', async () => {
    const sender = person()
    const deps = acceptDeps(sender)
    const out = await runAcceptDM(deps, incoming(sender), prints(sender))
    expect(out).toEqual({ ok: true, groupId: GROUP })
    expect(deps.acceptDM).toHaveBeenCalledExactlyOnceWith(GROUP, REQUEST_ID)
  })

  it('saves the sender’s keys on first sight and only then', async () => {
    const sender = person()
    const first = acceptDeps(sender)
    await runAcceptDM(first, incoming(sender), prints(sender))
    expect(first.pinKeys).toHaveBeenCalledWith(OTHER, [sender.edB64], sender.xB64, 0)

    const again = acceptDeps(sender, { pins: [pinOf(sender, OTHER)] })
    await runAcceptDM(again, incoming(sender), prints(sender))
    expect(again.pinKeys).not.toHaveBeenCalled()
  })

  it('does not accept if the sender’s keys are not the ones that were confirmed', async () => {
    const shown = person()
    const swapped = person()
    const deps = acceptDeps(swapped)
    const out = await runAcceptDM(deps, incoming(swapped), prints(shown))
    expect(out).toEqual({ ok: false, kind: 'keysChanged' })
    expect(deps.acceptDM).not.toHaveBeenCalled()
    expect(deps.pinKeys).not.toHaveBeenCalled()
  })

  it('re-verifies at accept time: a DM that no longer verifies is not accepted', async () => {
    const sender = person()
    const deps = acceptDeps(sender)
    const forged = incoming(sender, { signWith: person().signing })
    expect(await runAcceptDM(deps, forged, prints(sender))).toEqual({
      ok: false,
      kind: 'badAdmission',
    })
    expect(deps.acceptDM).not.toHaveBeenCalled()
  })

  it('does not accept if the sender’s keys could not be saved', async () => {
    const sender = person()
    const deps = acceptDeps(sender, {
      pinKeys: vi.fn(async () => {
        throw new Error('disk')
      }),
    })
    expect(await runAcceptDM(deps, incoming(sender), prints(sender))).toMatchObject({
      ok: false,
      kind: 'unchecked',
    })
    expect(deps.acceptDM).not.toHaveBeenCalled()
  })

  describe('what the server says', () => {
    async function acceptWith(error: unknown) {
      const sender = person()
      const deps = acceptDeps(sender, {
        acceptDM: vi.fn(async () => {
          throw error
        }),
      })
      return runAcceptDM(deps, incoming(sender), prints(sender))
    }

    it.each([
      [409, 'keys_changed', 'myKeysChanged'],
      [409, 'already_member', 'alreadyMember'],
      [409, 'request_changed', 'requestChanged'],
      [410, 'account_deleted', 'accountDeleted'],
    ] as const)('maps %s %s to %s', async (status, code, kind) => {
      expect(await acceptWith(new ApiError(status, 'words', code))).toMatchObject({
        ok: false,
        kind,
      })
    })

    it('maps 404, 401, other 4xx and unknown failures', async () => {
      expect(await acceptWith(new ApiError(404, 'no'))).toMatchObject({ kind: 'goneRequest' })
      expect(await acceptWith(new ApiError(401, 'no'))).toMatchObject({ kind: 'authRequired' })
      expect(await acceptWith(new ApiError(400, 'bad'))).toMatchObject({
        kind: 'rejected',
        message: 'bad',
      })
      expect(await acceptWith(new TypeError('network'))).toMatchObject({ kind: 'ambiguous' })
      expect(await acceptWith(new ApiError(500, 'oops'))).toMatchObject({ kind: 'ambiguous' })
    })

    it('explains my own keys_changed by what the person can do', async () => {
      const out = await acceptWith(new ApiError(409, 'words', 'keys_changed'))
      if (out.ok) throw new Error('expected a failure')
      expect(acceptDMFailureMessage(out)).toMatch(/decline/i)
    })
  })

  it('reloads the list exactly when the list moved', () => {
    expect(shouldReloadAfterAccept({ ok: true, groupId: GROUP })).toBe(true)
    for (const kind of ['requestChanged', 'goneRequest', 'alreadyMember', 'ambiguous'] as const) {
      expect(shouldReloadAfterAccept({ ok: false, kind })).toBe(true)
    }
    for (const kind of [
      'pinMismatch',
      'badAdmission',
      'notYourKeys',
      'myKeysChanged',
      'keysChanged',
    ] as const) {
      expect(shouldReloadAfterAccept({ ok: false, kind })).toBe(false)
    }
  })

  it('has a message for every failure it can return', () => {
    const kinds = [
      'pinMismatch',
      'keysChanged',
      'gone',
      'deleted',
      'self',
      'badAdmission',
      'notYourKeys',
      'myKeysChanged',
      'alreadyMember',
      'requestChanged',
      'goneRequest',
      'accountDeleted',
      'authRequired',
      'coldKeys',
      'ambiguous',
    ] as const
    for (const kind of kinds) {
      expect(acceptDMFailureMessage({ ok: false, kind }).length).toBeGreaterThan(10)
    }
  })
})

describe('runDeclineDM', () => {
  it('declines the DM it was given', async () => {
    const sender = person()
    const deps = acceptDeps(sender)
    expect(await runDeclineDM(deps, incoming(sender))).toEqual({ ok: true })
    expect(deps.declineDM).toHaveBeenCalledExactlyOnceWith(GROUP, REQUEST_ID)
  })

  it('needs no check of the sender: declining writes nothing about them', async () => {
    const sender = person()
    const deps = acceptDeps(sender, { served: undefined })
    expect(await runDeclineDM(deps, incoming(sender))).toEqual({ ok: true })
    expect(deps.pinKeys).not.toHaveBeenCalled()
  })

  it('says when it is already gone or changed, and reports other failures', async () => {
    const sender = person()
    const run = (error: unknown) =>
      runDeclineDM(
        acceptDeps(sender, {
          declineDM: vi.fn(async () => {
            throw error
          }),
        }),
        incoming(sender),
      )
    expect(await run(new ApiError(404, 'no'))).toMatchObject({ ok: false, gone: true })
    expect(await run(new ApiError(409, 'changed', 'request_changed'))).toMatchObject({
      ok: false,
      gone: true,
    })
    expect(await run(new ApiError(401, 'no'))).toMatchObject({ ok: false, message: /log in/i })
    expect(await run(new ApiError(400, 'bad'))).toEqual({ ok: false, message: 'bad' })
    expect(await run(new TypeError('network'))).toMatchObject({ ok: false, message: /try again/i })
  })
})
