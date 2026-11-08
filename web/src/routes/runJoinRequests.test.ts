import { describe, expect, it, vi } from 'vitest'
import { ApiError } from '@/lib/api/auth'
import type { GroupDetail } from '@/lib/api/groups'
import type { JoinRequestEntry } from '@/lib/api/joinRequests'
import type { UserProjection } from '@/lib/api/users'
import { bytesToBase64 } from '@/lib/crypto/base64'
import * as ed25519 from '@/lib/crypto/ed25519'
import { fingerprint } from '@/lib/crypto/fingerprint'
import { joinRequestPayload } from '@/lib/crypto/joinRequest'
import { pinPayload, type PinRecord } from '@/lib/crypto/pin'
import { generateWrappingKey } from '@/lib/crypto/x25519'
import {
  joinApprovalFailureMessage,
  prepareJoinApproval,
  runApproveJoinRequest,
  runDenyJoinRequest,
  runRequestToJoin,
  runWithdrawJoinRequest,
  shouldReloadAfterJoinApproval,
  type JoinApprovalDeps,
  type RequestToJoinDeps,
} from './runJoinRequests'

const GROUP = '11111111-1111-4111-8111-111111111111'
const SELF = '22222222-2222-4222-8222-222222222222'
const REQUESTER = '33333333-3333-4333-8333-333333333333'
const REQUEST_ID = '44444444-4444-4444-8444-444444444444'
const GRANT_REF = 'GRANT#abc'
const DAY = '2026-11-08'
const NOW = Date.parse(`${DAY}T12:00:00Z`)

const own = ed25519.generateSigningKey()
const ownPub = bytesToBase64(own.publicKey)

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

function entryFor(p: Person, over: Partial<JoinRequestEntry> = {}): JoinRequestEntry {
  const requestId = over.requestId ?? REQUEST_ID
  const userId = over.userId ?? REQUESTER
  const sig = ed25519.sign(
    p.signing,
    ed25519.SigningContext.JoinRequest,
    joinRequestPayload(requestId, GROUP, userId, p.signing.publicKey, p.xRaw),
  )
  return {
    userId,
    requestId,
    ed25519PublicKey: p.edB64,
    x25519PublicKey: p.xB64,
    signature: bytesToBase64(sig),
    day: DAY,
    ...over,
  }
}

function served(p: Person, over: Partial<UserProjection> = {}): UserProjection {
  return {
    userId: REQUESTER,
    username: 'rex',
    signingPublicKey: p.edB64,
    wrappingPublicKey: p.xB64,
    supersededSigningKeys: [],
    keyEpoch: 0,
    ...over,
  }
}

/** A pin the approver saved of `p`, signed by the approver. */
function pinOf(p: Person, keyEpoch = 0): PinRecord {
  const signedDay = '2026-11-01'
  const sig = ed25519.sign(
    own,
    ed25519.SigningContext.Pin,
    pinPayload(SELF, REQUESTER, own.publicKey, p.xRaw, [p.signing.publicKey], keyEpoch, signedDay),
  )
  return {
    pinnedUserId: REQUESTER,
    signingPublicKeys: [p.edB64],
    wrappingPublicKey: p.xB64,
    pinnerSigningPublicKey: ownPub,
    signature: bytesToBase64(sig),
    keyEpoch,
    signedDay,
  }
}

const DETAIL = {
  groupId: GROUP,
  visibility: 'public',
  role: 'admin',
  generation: 3,
  myGrantSortKey: GRANT_REF,
  wrappedGroupKey: { ephemeralPub: 'e', nonce: 'n', ciphertext: 'c' },
} as unknown as GroupDetail

const WRAPPED = { ephemeralPub: 'we', nonce: 'wn', ciphertext: 'wc' }

function approvalDeps(
  p: Person,
  over: Partial<JoinApprovalDeps> & {
    served?: UserProjection | undefined
    pins?: PinRecord[]
  } = {},
) {
  const { served: servedOverride, pins, ...rest } = over
  const projection = 'served' in over ? servedOverride : served(p)
  const deps = {
    selfUserId: SELF,
    now: () => NOW,
    ownSigningKey: vi.fn(async () => ownPub),
    getGroup: vi.fn(async () => DETAIL),
    getUsers: vi.fn(async () => new Map(projection ? [[REQUESTER, projection]] : [])),
    listPins: vi.fn(async () => pins ?? []),
    pinKeys: vi.fn(async () => undefined),
    rewrapCrypto: vi.fn(async () => ({ wraps: [{ userId: REQUESTER, wrappedKey: WRAPPED }] })),
    signReadmission: vi.fn(async (req: { inviterGrantRef: string; day: string }) => ({
      inviterGrantRef: req.inviterGrantRef,
      day: req.day,
      signature: 'admission-sig',
    })),
    approveJoinRequest: vi.fn(async () => undefined),
    denyJoinRequest: vi.fn(async () => undefined),
    ...rest,
  }
  return deps as typeof deps & JoinApprovalDeps
}

describe('runRequestToJoin', () => {
  function deps(over: Partial<RequestToJoinDeps> = {}) {
    const requester = person()
    const sent: unknown[] = []
    const d: RequestToJoinDeps = {
      selfUserId: REQUESTER,
      newRequestId: () => REQUEST_ID,
      signJoinRequest: async (req) => ({
        signature: bytesToBase64(
          ed25519.sign(
            requester.signing,
            ed25519.SigningContext.JoinRequest,
            joinRequestPayload(
              req.requestId,
              req.groupId,
              req.userId,
              requester.signing.publicKey,
              requester.xRaw,
            ),
          ),
        ),
      }),
      createJoinRequest: async (groupId, body) => {
        sent.push({ groupId, body })
      },
      ...over,
    }
    return { d, sent, requester }
  }

  it('signs the request id and group and sends exactly that id with the signature', async () => {
    const { d, sent } = deps()
    expect(await runRequestToJoin(d, GROUP)).toEqual({ ok: true })
    expect(sent).toHaveLength(1)
    const only = sent[0] as { groupId: string; body: { requestId: string; signature: string } }
    expect(only.groupId).toBe(GROUP)
    expect(only.body.requestId).toBe(REQUEST_ID)
    expect(only.body.signature.length).toBeGreaterThan(40)
  })

  it.each([
    ['already_member', 409, 'alreadyMember'],
    ['request_pending', 409, 'pending'],
    ['request_cooling_off', 409, 'coolingOff'],
    ['keys_changed', 409, 'keysChanged'],
  ] as const)('maps %s to %s', async (code, status, kind) => {
    const { d } = deps({
      createJoinRequest: async () => {
        throw new ApiError(
          status,
          'your last request was declined; ask again after 2026-11-15',
          code,
        )
      },
    })
    const out = await runRequestToJoin(d, GROUP)
    expect(out).toMatchObject({ ok: false, kind })
  })

  it('keeps the server wording for a cool-off, which names the day', async () => {
    const { d } = deps({
      createJoinRequest: async () => {
        throw new ApiError(409, 'you can ask again after 2026-11-15', 'request_cooling_off')
      },
    })
    expect(await runRequestToJoin(d, GROUP)).toMatchObject({
      message: 'you can ask again after 2026-11-15',
    })
  })

  it('says a private or missing group is not open, on 404', async () => {
    const { d } = deps({
      createJoinRequest: async () => {
        throw new ApiError(404, 'no such public group')
      },
    })
    expect(await runRequestToJoin(d, GROUP)).toMatchObject({ ok: false, kind: 'notFound' })
  })

  it('does not say it was sent when the network failed', async () => {
    const { d } = deps({
      createJoinRequest: async () => {
        throw new TypeError('network')
      },
    })
    expect(await runRequestToJoin(d, GROUP)).toMatchObject({ ok: false, kind: 'ambiguous' })
  })

  it('sends nothing when signing fails', async () => {
    const createJoinRequest = vi.fn()
    const { d } = deps({
      signJoinRequest: async () => {
        throw new Error('boom')
      },
      createJoinRequest,
    })
    expect(await runRequestToJoin(d, GROUP)).toMatchObject({ ok: false, kind: 'rejected' })
    expect(createJoinRequest).not.toHaveBeenCalled()
  })
})

describe('runWithdrawJoinRequest and runDenyJoinRequest', () => {
  it('report the server wording of a refusal', async () => {
    const withdraw = await runWithdrawJoinRequest(
      {
        withdrawJoinRequest: async () => {
          throw new ApiError(
            409,
            'this request was declined and cannot be withdrawn',
            'request_denied',
          )
        },
      },
      GROUP,
    )
    expect(withdraw).toEqual({
      ok: false,
      message: 'this request was declined and cannot be withdrawn',
    })
    const deny = await runDenyJoinRequest(
      {
        denyJoinRequest: async () => {
          throw new ApiError(404, 'no pending request from this user')
        },
      },
      GROUP,
      REQUESTER,
    )
    expect(deny).toEqual({ ok: false, message: 'no pending request from this user' })
  })

  it('succeed when the server does', async () => {
    const denyJoinRequest = vi.fn(async () => undefined)
    expect(await runDenyJoinRequest({ denyJoinRequest }, GROUP, REQUESTER)).toEqual({ ok: true })
    expect(denyJoinRequest).toHaveBeenCalledWith(GROUP, REQUESTER)
  })
})

describe('prepareJoinApproval', () => {
  it('returns the fingerprint of the signed keys and says it is a first sight', async () => {
    const p = person()
    const out = await prepareJoinApproval(approvalDeps(p), GROUP, entryFor(p))
    expect(out).toEqual({
      ok: true,
      fingerprint: fingerprint(p.signing.publicKey, p.xRaw),
      firstSight: true,
    })
  })

  it('says it is not a first sight when a saved copy matches', async () => {
    const p = person()
    const out = await prepareJoinApproval(approvalDeps(p, { pins: [pinOf(p)] }), GROUP, entryFor(p))
    expect(out).toMatchObject({ ok: true, firstSight: false })
  })

  it('refuses a signature made by someone else, before reading anything about them', async () => {
    const p = person()
    const impostor = person()
    const deps = approvalDeps(p)
    const forged = { ...entryFor(p), signature: entryFor(impostor).signature }
    expect(await prepareJoinApproval(deps, GROUP, forged)).toMatchObject({
      ok: false,
      kind: 'badSignature',
    })
    expect(deps.getUsers).not.toHaveBeenCalled()
  })

  it('refuses a request signed for another group', async () => {
    const p = person()
    const deps = approvalDeps(p)
    const other = '55555555-5555-4555-8555-555555555555'
    expect(await prepareJoinApproval(deps, other, entryFor(p))).toMatchObject({
      ok: false,
      kind: 'badSignature',
    })
  })

  it('refuses a request filed under another user id than the one signed', async () => {
    const p = person()
    const entry = { ...entryFor(p), userId: '66666666-6666-4666-8666-666666666666' }
    expect(await prepareJoinApproval(approvalDeps(p), GROUP, entry)).toMatchObject({
      ok: false,
      kind: 'badSignature',
    })
  })

  it('refuses a request whose key fields were swapped after signing', async () => {
    const p = person()
    const other = person()
    const entry = { ...entryFor(p), x25519PublicKey: other.xB64 }
    expect(await prepareJoinApproval(approvalDeps(p), GROUP, entry)).toMatchObject({
      ok: false,
      kind: 'badSignature',
    })
  })

  it('blocks when the keys differ from the saved copy', async () => {
    const saved = person()
    const p = person()
    const deps = approvalDeps(p, { pins: [pinOf(saved)] })
    expect(await prepareJoinApproval(deps, GROUP, entryFor(p))).toMatchObject({
      ok: false,
      kind: 'pinMismatch',
    })
  })

  it('says to ask again when the served keys are no longer the signed ones', async () => {
    const p = person()
    const rotated = person()
    const deps = approvalDeps(p, { served: served(rotated, { keyEpoch: 1 }) })
    expect(await prepareJoinApproval(deps, GROUP, entryFor(p))).toMatchObject({
      ok: false,
      kind: 'requesterKeysChanged',
    })
  })

  it('refuses a deleted account and a missing one', async () => {
    const p = person()
    expect(
      await prepareJoinApproval(
        approvalDeps(p, { served: served(p, { deleted: true }) }),
        GROUP,
        entryFor(p),
      ),
    ).toMatchObject({ ok: false, kind: 'deleted' })
    expect(
      await prepareJoinApproval(approvalDeps(p, { served: undefined }), GROUP, entryFor(p)),
    ).toMatchObject({ ok: false, kind: 'gone' })
  })

  it('refuses to approve your own request', async () => {
    const p = person()
    expect(
      await prepareJoinApproval(approvalDeps(p), GROUP, entryFor(p, { userId: SELF })),
    ).toMatchObject({ ok: false, kind: 'rejected' })
  })

  it('does not proceed when the pins cannot be read', async () => {
    const p = person()
    const deps = approvalDeps(p, {
      listPins: vi.fn(async () => {
        throw new Error('down')
      }),
    })
    expect(await prepareJoinApproval(deps, GROUP, entryFor(p))).toMatchObject({
      ok: false,
      kind: 'unchecked',
    })
  })
})

describe('runApproveJoinRequest', () => {
  it('wraps to the signed key, signs the admission with the request id, and sends both', async () => {
    const p = person()
    const entry = entryFor(p)
    const deps = approvalDeps(p)
    const out = await runApproveJoinRequest(
      deps,
      GROUP,
      entry,
      fingerprint(p.signing.publicKey, p.xRaw),
    )
    expect(out).toEqual({ ok: true })
    expect(deps.rewrapCrypto).toHaveBeenCalledWith(
      expect.objectContaining({
        groupId: GROUP,
        ownGeneration: 3,
        recipients: [{ userId: REQUESTER, x25519PublicKey: p.xB64 }],
      }),
    )
    expect(deps.signReadmission).toHaveBeenCalledWith(
      expect.objectContaining({
        groupId: GROUP,
        subjectUserId: REQUESTER,
        subjectEd25519PublicKey: p.edB64,
        subjectX25519PublicKey: p.xB64,
        inviteId: REQUEST_ID,
        inviterGrantRef: GRANT_REF,
        day: DAY,
        generation: 3,
      }),
    )
    expect(deps.approveJoinRequest).toHaveBeenCalledWith(GROUP, REQUESTER, {
      requestId: REQUEST_ID,
      wrappedGroupKey: WRAPPED,
      generation: 3,
      admission: { inviterGrantRef: GRANT_REF, day: DAY, signature: 'admission-sig' },
    })
  })

  it('saves their keys on a first sight, and not when they already matched', async () => {
    const p = person()
    const first = approvalDeps(p)
    await runApproveJoinRequest(first, GROUP, entryFor(p), fingerprint(p.signing.publicKey, p.xRaw))
    expect(first.pinKeys).toHaveBeenCalledWith(REQUESTER, [p.edB64], p.xB64, 0)
    const again = approvalDeps(p, { pins: [pinOf(p)] })
    await runApproveJoinRequest(again, GROUP, entryFor(p), fingerprint(p.signing.publicKey, p.xRaw))
    expect(again.pinKeys).not.toHaveBeenCalled()
  })

  it('wraps nothing when the confirmed fingerprint is not the one checked now', async () => {
    const p = person()
    const deps = approvalDeps(p)
    const out = await runApproveJoinRequest(
      deps,
      GROUP,
      entryFor(p),
      fingerprint(own.publicKey, p.xRaw),
    )
    expect(out).toMatchObject({ ok: false, kind: 'keysChanged' })
    expect(deps.rewrapCrypto).not.toHaveBeenCalled()
    expect(deps.signReadmission).not.toHaveBeenCalled()
    expect(deps.approveJoinRequest).not.toHaveBeenCalled()
    expect(deps.pinKeys).not.toHaveBeenCalled()
  })

  it('wraps nothing when the signature does not verify, even with a matching fingerprint', async () => {
    const p = person()
    const impostor = person()
    const deps = approvalDeps(p)
    const forged = { ...entryFor(p), signature: entryFor(impostor).signature }
    const out = await runApproveJoinRequest(
      deps,
      GROUP,
      forged,
      fingerprint(p.signing.publicKey, p.xRaw),
    )
    expect(out).toMatchObject({ ok: false, kind: 'badSignature' })
    expect(deps.rewrapCrypto).not.toHaveBeenCalled()
  })

  it('wraps nothing on a pin mismatch', async () => {
    const saved = person()
    const p = person()
    const deps = approvalDeps(p, { pins: [pinOf(saved)] })
    const out = await runApproveJoinRequest(
      deps,
      GROUP,
      entryFor(p),
      fingerprint(p.signing.publicKey, p.xRaw),
    )
    expect(out).toMatchObject({ ok: false, kind: 'pinMismatch' })
    expect(deps.rewrapCrypto).not.toHaveBeenCalled()
  })

  it('wraps nothing for a plain member, a missing grant, a running rotation or a missing own key', async () => {
    const p = person()
    const fp = fingerprint(p.signing.publicKey, p.xRaw)
    const cases: [Record<string, unknown>, string][] = [
      [{ role: 'member' }, 'forbidden'],
      [{ myGrantSortKey: '' }, 'unchecked'],
      [{ rotation: { generation: 4 } as GroupDetail['rotation'] }, 'rotationRunning'],
      [{ wrappedGroupKey: undefined }, 'unchecked'],
    ]
    for (const [over, kind] of cases) {
      const deps = approvalDeps(p, {
        getGroup: vi.fn(async () => ({ ...DETAIL, ...over }) as GroupDetail),
      })
      const out = await runApproveJoinRequest(deps, GROUP, entryFor(p), fp)
      expect(out, kind).toMatchObject({ ok: false, kind })
      expect(deps.rewrapCrypto).not.toHaveBeenCalled()
      expect(deps.approveJoinRequest).not.toHaveBeenCalled()
    }
  })

  it.each([
    ['group_full', 409, 'groupFull'],
    ['requester_keys_changed', 409, 'requesterKeysChanged'],
    ['already_member', 409, 'alreadyMember'],
    ['request_changed', 409, 'requestChanged'],
    ['grantor_ref_stale', 409, 'stale'],
    ['grantor_changed', 409, 'stale'],
    ['requester_deleted', 410, 'deleted'],
    ['bad_signature', 400, 'requesterKeysChanged'],
  ] as const)('maps the server code %s to %s', async (code, status, kind) => {
    const p = person()
    const deps = approvalDeps(p, {
      approveJoinRequest: vi.fn(async () => {
        throw new ApiError(status, 'x', code)
      }),
    })
    const out = await runApproveJoinRequest(
      deps,
      GROUP,
      entryFor(p),
      fingerprint(p.signing.publicKey, p.xRaw),
    )
    expect(out).toMatchObject({ ok: false, kind })
  })

  it('maps a lost reply to ambiguous and a bad clock to its own message', async () => {
    const p = person()
    const fp = fingerprint(p.signing.publicKey, p.xRaw)
    const lost = approvalDeps(p, {
      approveJoinRequest: vi.fn(async () => {
        throw new TypeError('network')
      }),
    })
    expect(await runApproveJoinRequest(lost, GROUP, entryFor(p), fp)).toMatchObject({
      ok: false,
      kind: 'ambiguous',
    })
    const skew = approvalDeps(p, {
      approveJoinRequest: vi.fn(async () => {
        throw new ApiError(400, 'x', 'clock_skew')
      }),
    })
    const out = await runApproveJoinRequest(skew, GROUP, entryFor(p), fp)
    expect(out).toMatchObject({ ok: false, kind: 'rejected' })
    expect(joinApprovalFailureMessage(out as never)).toMatch(/date|time|clock/i)
  })

  it('keeps a group_full request pending: the list is not reloaded for it', () => {
    expect(shouldReloadAfterJoinApproval({ ok: false, kind: 'groupFull' })).toBe(false)
    expect(shouldReloadAfterJoinApproval({ ok: true })).toBe(true)
    expect(shouldReloadAfterJoinApproval({ ok: false, kind: 'requestChanged' })).toBe(true)
  })
})
