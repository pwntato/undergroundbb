package crypto

// JoinRequestPayload builds the canonical byte string a requester signs to
// ask to join a public group -- docs/DESIGN.md, "Visibility -- private and
// public groups" (#72). It is the invite handshake's step 2 payload with the
// direction reversed: the requester signs their own two public keys, and an
// admin or ambassador wraps the group key to the keys that were signed.
//
// requestID is a fresh random UUID the requester picks, so one signature
// cannot stand in for another request of the same user to the same group
// (the REQ# row has one slot per user per group, and a new request after a
// denial's cool-off must carry a new signature). groupID binds the request to
// one group. Both keys are the requester's CURRENT keys; the approver's client
// checks them against what it has pinned and against the user the server
// names before it wraps anything.
//
// What this does NOT give is the invite's protection against a server that
// substitutes keys: that comes from invite_mac, whose secret travels in the
// link, and a stranger asking to join has no link. A first request from
// someone the approver has never seen is trust on first use; see
// docs/THREAT_MODEL.md.
//
// Sign this payload under ContextJoinRequest. Same length-prefixed encoding as
// InviteAcceptancePayload, and the same permanent-lockout warning: this must
// never change once a real request has been signed under it.
func JoinRequestPayload(requestID, groupID string, requesterEd25519PublicKey, requesterX25519PublicKey []byte) []byte {
	fields := [][]byte{
		[]byte(requestID),
		[]byte(groupID),
		requesterEd25519PublicKey,
		requesterX25519PublicKey,
	}
	return lengthPrefixedConcat(fields)
}
