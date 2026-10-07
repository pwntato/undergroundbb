// The real network and worker wiring for runRotation.ts, shared by every
// screen that starts or resumes a key rotation (removing a member, loading a
// group as an admin). Kept out of the screens so there is one definition of
// how a first-sight pin is signed and stored.

import { listAllPins, putPin } from '@/lib/api/pins'
import { completeRotation, getGroup, listMembers, rewrapMembers } from '@/lib/api/groups'
import { getUsers } from '@/lib/api/users'
import { getOwnSigningKey, rewrapGroupKey, signPin } from '@/lib/crypto/worker-client'
import { ownSigningKeyWithFallback } from '@/lib/session/ownSigningKey'
import { listAllMembers } from './runGroupMembers'
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
    listAllMembers: (groupId) => listAllMembers({ listMembers }, groupId),
    getUsers,
    ownSigningKey: () => ownSigningKeyWithFallback(userId, getOwnSigningKey),
    listPins: listAllPins,
    pinKeys: makePinKeys(userId),
    rewrapCrypto: rewrapGroupKey,
    rewrapMembers,
    completeRotation,
  }
}
