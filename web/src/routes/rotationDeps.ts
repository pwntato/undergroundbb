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
  takeOverRotation,
  rewrapMembers,
} from '@/lib/api/groups'
import { getUsers } from '@/lib/api/users'
import {
  getOwnSigningKey,
  rewrapGroupKey,
  signPin,
  signReadmission,
  startGroupRotation,
} from '@/lib/crypto/worker-client'
import { readAnchorPin, writeAnchorPin } from '@/lib/groups/anchorPin'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { listAllMembers } from './runGroupMembers'
import type { ReadmitDeps } from './runReadmit'
import type { RotationDeps } from './runRotation'

/** Signs a pin of someone's served keys with the caller's key and stores it. */
export function makePinKeys(userId: string): RotationDeps['pinKeys'] {
  return async (pinnedUserId, signingPublicKeys, wrappingPublicKey) => {
    const signed = await signPin({ userId, pinnedUserId, signingPublicKeys, wrappingPublicKey })
    await putPin(pinnedUserId, { signingPublicKeys, wrappingPublicKey, ...signed })
  }
}

export function makeRotationDeps(userId: string): RotationDeps {
  return {
    selfUserId: userId,
    getGroup,
    getKeychain,
    listAllMembers: (groupId) => listAllMembers({ listMembers }, groupId),
    getUsers,
    listGrants,
    listDesignations,
    listAdmissions,
    readPin: (g) => readAnchorPin(userId, g),
    writePin: (g, pin) => writeAnchorPin(userId, g, pin),
    ownSigningKey: () => ownSigningKeyWithFallback(userId, getOwnSigningKey),
    listPins: listAllPins,
    pinKeys: makePinKeys(userId),
    rewrapCrypto: rewrapGroupKey,
    rewrapMembers,
    completeRotation,
    takeOverCrypto: startGroupRotation,
    takeOverRotation,
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
