// The real network and worker wiring for runRotation.ts, shared by every
// screen that starts or resumes a key rotation (removing a member, loading a
// group as an admin). Kept out of the screens so there is one definition of
// how a first-sight pin is signed and stored.

import { listAllPins, putPin } from '@/lib/api/pins'
import {
  completeRotation,
  getGroup,
  getKeychain,
  listAdmissions,
  listDesignations,
  listGrants,
  listMembers,
  readmitMember,
  approveRekey,
  approveRewrap,
  selfRekey,
  selfWrap,
  takeOverRotation,
  rewrapMembers,
} from '@/lib/api/groups'
import { deleteHandoff } from '@/lib/api/keyRotation'
import { getUserDetail, getUsers } from '@/lib/api/users'
import {
  getOwnSigningKey,
  rewrapGroupKey,
  signPin,
  signReadmission,
  startApprovalRekey,
  startGroupRotation,
  selfWrapFromHandoff,
  startSelfRekey,
} from '@/lib/crypto/worker-client'
import { readAnchorPin, writeAnchorPin } from '@/lib/groups/anchorPin'
import { makeOwnKeyHistoryLoader } from '@/lib/session/ownKeyHistory'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { listAllMembers } from './runGroupMembers'
import type { AcceptKeyChangeDeps } from './runAcceptKeyChange'
import type { ApproveDeps } from './runApprove'
import type { ReadmitDeps } from './runReadmit'
import type { RotationDeps } from './runRotation'
import type { SelfRekeyDeps } from './runSelfRekey'

/** Signs a pin of someone's served keys with the caller's key and stores it. */
export function makePinKeys(userId: string): RotationDeps['pinKeys'] {
  return async (pinnedUserId, signingPublicKeys, wrappingPublicKey, keyEpoch) => {
    const signed = await signPin({
      userId,
      pinnedUserId,
      signingPublicKeys,
      wrappingPublicKey,
      keyEpoch,
    })
    await putPin(pinnedUserId, { signingPublicKeys, wrappingPublicKey, ...signed })
  }
}

export function makeRotationDeps(userId: string): RotationDeps {
  const ownKeyHistory = makeOwnKeyHistoryLoader(userId)
  return {
    selfUserId: userId,
    getGroup,
    getKeychain,
    listAllMembers: (groupId) => listAllMembers({ listMembers }, groupId),
    getUsers,
    getUserDetail,
    listGrants,
    listDesignations,
    listAdmissions,
    readPin: (g) => readAnchorPin(userId, g),
    writePin: (g, pin) => writeAnchorPin(userId, g, pin),
    ownSigningKey: () => ownSigningKeyWithFallback(userId, getOwnSigningKey),
    loadOwnKeyHistory: ownKeyHistory,
    ownKeyHistoryFailure: ownKeyHistory.failure,
    listPins: listAllPins,
    pinKeys: makePinKeys(userId),
    rewrapCrypto: rewrapGroupKey,
    rewrapMembers,
    completeRotation,
    takeOverCrypto: startGroupRotation,
    takeOverRotation,
  }
}

/** The rotation wiring plus what the self re-key from a handoff row needs (#62). */
export function makeSelfRekeyDeps(userId: string): SelfRekeyDeps {
  return {
    ...makeRotationDeps(userId),
    startSelfRekeyCrypto: startSelfRekey,
    selfRekey,
    selfWrapCrypto: selfWrapFromHandoff,
    selfWrap,
    deleteHandoff,
  }
}

/** The rotation wiring plus what a re-admission needs to sign and send (#178 part 5b). */
export function makeReadmitDeps(userId: string): ReadmitDeps {
  return {
    ...makeRotationDeps(userId),
    signReadmission,
    readmitMember,
    newInviteId: () => crypto.randomUUID(),
  }
}

/** The rotation wiring plus what approving a dormant member's new keys needs (#62). */
export function makeApproveDeps(userId: string): ApproveDeps {
  return {
    ...makeRotationDeps(userId),
    approveRewrap,
    approveRekey,
    startApprovalCrypto: startApprovalRekey,
  }
}

/** What accepting another user's key change needs: their served keys and chain, your pins, and a pin write. */
export function makeAcceptDeps(userId: string): AcceptKeyChangeDeps {
  const ownKeyHistory = makeOwnKeyHistoryLoader(userId)
  return {
    selfUserId: userId,
    getUserDetail,
    ownSigningKey: () => ownSigningKeyWithFallback(userId, getOwnSigningKey),
    listPins: listAllPins,
    loadOwnKeyHistory: ownKeyHistory,
    ownKeyHistoryFailure: ownKeyHistory.failure,
    pinKeys: makePinKeys(userId),
  }
}
