// Join requests (#72): the payload a requester signs to ask to join a public group. Mirrors
// internal/crypto/join_request.go byte for byte (the "join_request" vectors pin both).

import { lengthPrefixedConcat } from './payload.js'

/**
 * The bytes a requester signs under SigningContext.JoinRequest: a fresh request id, the group, the
 * requester's own uuid, and their current Ed25519 and X25519 public keys. The uuid is signed because
 * for a join request it is the only identity claim (an invite gets that binding from the link it was
 * sent to): without it, a request signed by one user would be a valid signature for the row the
 * server files under another. An admin or ambassador's client verifies the signature, checks the
 * keys against what it has pinned and the uuid against the user it is shown, and wraps the group key
 * to the keys that were signed. Unlike an invite there is no link secret, so a first request from
 * someone the approver has never seen is trust on first use (docs/THREAT_MODEL.md). This must never
 * change once a real request has been signed under it.
 */
export function joinRequestPayload(
  requestId: string,
  groupId: string,
  requesterUserId: string,
  requesterEd25519PublicKey: Uint8Array,
  requesterX25519PublicKey: Uint8Array,
): Uint8Array {
  const encoder = new TextEncoder()
  return lengthPrefixedConcat([
    encoder.encode(requestId),
    encoder.encode(groupId),
    encoder.encode(requesterUserId),
    requesterEd25519PublicKey,
    requesterX25519PublicKey,
  ])
}
