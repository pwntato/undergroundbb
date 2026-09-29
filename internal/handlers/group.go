package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// maxGroupNameLen and maxGroupDescriptionLen bound the plaintext fields a
// PUBLIC group submits. There is no equivalent bound documented in
// docs/DESIGN.md -- like usernamePattern's bounds, this is a server-side
// policy choice rather than a protocol requirement, generous relative to
// any real name or description but well short of turning this endpoint into
// an arbitrary-text store.
const (
	maxGroupNameLen        = 200
	maxGroupDescriptionLen = 2000
)

// maxGroupCiphertextLen bounds a PRIVATE group's encrypted name/description
// ciphertext -- generous relative to what AES-256-GCM over a name or
// description this short actually produces, same reasoning as
// maxCiphertextLen in register.go.
const maxGroupCiphertextLen = 4096

// maxSignatureLen bounds an Ed25519 signature field. Ed25519 signatures are
// exactly 64 bytes; a wantLen check below already enforces that exactly, so
// this constant exists only to satisfy decodeBase64Field's signature the
// same way maxVerifierLen does for a field that's already exact-length
// checked.
const maxSignatureLen = 64

// grantDaySkewTolerance bounds how far a client-chosen RootGrantSortKey's
// day may drift from the server's own UTC clock, in either direction --
// generous enough to absorb ordinary client/server clock drift and request
// latency without opening a window a client could use to meaningfully
// backdate or postdate a grant relative to a real rotation event, which
// happens on the scale of DESIGN.md's key-history retention, not hours.
const grantDaySkewTolerance = 2 * time.Hour

// maxCreateGroupBodyBytes bounds the request body -- same reasoning as
// maxRegisterBodyBytes, sized generously above the largest legitimate
// payload (a private group's two ciphertext fields plus two signatures).
const maxCreateGroupBodyBytes = 32 * 1024

// createGroupRequest is the wire shape of POST /api/groups. See
// docs/DESIGN.md, "Groups" and "Roles and the chain of trust."
//
// The client generates the group key, wraps it to its own X25519 public key
// (crypto.Wrap), and signs both the trust anchor (crypto.TrustAnchorPayload
// under crypto.ContextTrustAnchor) and the self-signed root role grant
// (crypto.RoleGrantPayload under crypto.ContextRoleGrant, with an empty
// grantorGrantRef -- see models.RoleGrant's own doc comment on why the root
// grant has no predecessor to reference). CreatorSigningPublicKey is NOT
// read from this request for anything security-relevant -- see createGroup's
// own doc comment on why it is re-derived from the caller's own
// session-authenticated PROFILE instead, and is only decoded from the wire
// here in the sense that it never is: there is no such field, deliberately.
type createGroupRequest struct {
	// GroupID is client-generated, exactly like registerRequest.UserID and
	// for the identical reason: TrustAnchorPayload and RoleGrantPayload both
	// bind the group id into what TrustAnchorSignature/RootGrantSignature
	// cover, so the client must already know the real gid before it signs
	// either one -- a server-assigned id handed back only after this request
	// arrives would be signing nothing the server could ever verify against.
	// idgen.ValidUUID enforces the same exact shape idgen.UUID() itself
	// produces, the same check register.go applies to UserID.
	GroupID string `json:"groupId"`

	Visibility string `json:"visibility"`

	// NamePlaintext and DescriptionPlaintext are set when Visibility is
	// "public"; NameCiphertext/DescriptionCiphertext when it is "private".
	// Exactly one pair is expected per Visibility -- validated below (both
	// that the pair matching Visibility is well-formed, and that the OTHER
	// pair is empty, PR #142 review), not by the JSON shape itself, matching
	// registerRequest's own field-by-field validation style rather than a
	// oneof encoded into the type system. Rejecting a populated off-visibility
	// pair, rather than silently ignoring it, matters specifically for a
	// private group carrying namePlaintext: ignoring it would still have let
	// a buggy client send a private group's plaintext name over the wire
	// with no error telling it that value was never stored.
	NamePlaintext         string      `json:"namePlaintext,omitempty"`
	DescriptionPlaintext  string      `json:"descriptionPlaintext,omitempty"`
	NameCiphertext        wrappedBlob `json:"nameCiphertext,omitempty"`
	DescriptionCiphertext wrappedBlob `json:"descriptionCiphertext,omitempty"`

	RevocationMode string `json:"revocationMode"`

	// ExpirationDays is the group's message-expiration policy, or 0 to mean
	// "never expire" -- see validateExpirationDays for how this is checked
	// against the deployment's config.AllowGroupExpirationOff and
	// config.DefaultExpirationDays.
	ExpirationDays int64 `json:"expirationDays"`

	// GroupKeyWrapped is the Generation 0 group key, ECIES-wrapped
	// (crypto.Wrap) to the creator's own X25519 public key -- their own
	// WrappingPublicKey, already on file from registration, not resent here.
	// A wrappedKey, not a wrappedBlob -- see models.WrappedKey's own doc
	// comment for why an ECIES wrap needs the ephemeral public key as a
	// third field alongside nonce/ciphertext.
	GroupKeyWrapped wrappedKey `json:"groupKeyWrapped"`

	// TrustAnchorSignature is crypto.Sign(creatorPriv, ContextTrustAnchor,
	// crypto.TrustAnchorPayload(creatorUUID, creatorSigningPublicKey, gid)) --
	// see createGroup's own doc comment for how gid is chosen and
	// creatorSigningPublicKey is sourced before this signature can be
	// verified.
	TrustAnchorSignature string `json:"trustAnchorSignature"`
	// RootGrantSortKey is the "GRANT#<uuid>#<YYYY-MM-DD>#<rand>" sort key
	// the root grant will be written under, client-generated (matching
	// GroupID's own reasoning): RoleGrantPayload now signs the grant's own
	// address (see that function's own doc comment for why), so the client
	// must choose it before signing, before this request is ever sent. The
	// server validates its shape and that its day is within clock-skew
	// tolerance of now -- see createGroup's own validation below -- rather
	// than trusting it outright.
	RootGrantSortKey string `json:"rootGrantSortKey"`
	// RootGrantSignature is crypto.Sign(creatorPriv, ContextRoleGrant,
	// crypto.RoleGrantPayload(gid, creatorUUID, "admin", rootGrantSortKey, "")).
	RootGrantSignature string `json:"rootGrantSignature"`
}

// createGroupResponse confirms the group was created and echoes back the
// client-chosen ids the client needs to address it -- GroupID to fetch or
// link to the group, and RootGrantSortKey so a caller that only kept the
// signed request around (not its own generated values) can still address
// (or a future grant can reference) the root grant it just wrote, without a
// separate query to discover it. Both are already known to the caller that
// sent this request; this is a convenience echo, not new information.
type createGroupResponse struct {
	GroupID          string `json:"groupId"`
	RootGrantSortKey string `json:"rootGrantSortKey"`
}

// createGroup implements POST /api/groups -- issue #34. Authenticated by
// requireSession (wired in RegisterRoutes).
//
// GroupID is client-generated (see createGroupRequest.GroupID's own doc
// comment for why: the signatures below must cover the real gid, which
// means the client has to know it before it signs, which means it cannot be
// something this handler hands back afterward). This handler validates its
// shape with idgen.ValidUUID and otherwise treats it exactly like
// register.go treats UserID: a value the server did not generate and so
// cannot assume is collision-free, guarded by db.CreateGroup's own
// attribute_not_exists(PK) condition (ErrGroupIDTaken) rather than trust.
//
// The GRANT# sort key is also client-generated, like GroupID -- see
// createGroupRequest.RootGrantSortKey's own doc comment for why
// RoleGrantPayload now signs the grant's own address. This handler
// validates its shape and day (idgen.ValidGrantSortKey, grantDaySkewTolerance)
// rather than generating it, the same "client decides, server checks"
// split GroupID gets.
func (h *Handler) createGroup(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxCreateGroupBodyBytes)
	var req createGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	if !idgen.ValidUUID(req.GroupID) {
		WriteError(w, http.StatusBadRequest, "groupId: must be a well-formed, lowercase UUIDv4")
		return
	}

	if req.Visibility != models.VisibilityPrivate && req.Visibility != models.VisibilityPublic {
		WriteError(w, http.StatusBadRequest, "visibility: must be \"private\" or \"public\"")
		return
	}
	if req.RevocationMode != models.RevocationRotating && req.RevocationMode != models.RevocationOpen {
		WriteError(w, http.StatusBadRequest, "revocationMode: must be \"rotating\" or \"open\"")
		return
	}

	expirationDays, err := validateExpirationDays(req.ExpirationDays, h.cfg.AllowGroupExpirationOff)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	var namePlaintext, descriptionPlaintext string
	var nameCiphertext, descriptionCiphertext *models.WrappedBlob
	if req.Visibility == models.VisibilityPublic {
		if !wrappedBlobEmpty(req.NameCiphertext) || !wrappedBlobEmpty(req.DescriptionCiphertext) {
			WriteError(w, http.StatusBadRequest, "nameCiphertext/descriptionCiphertext: must not be set for a public group")
			return
		}
		namePlaintext, err = validateGroupText(req.NamePlaintext, maxGroupNameLen, "namePlaintext", false)
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		descriptionPlaintext, err = validateGroupText(req.DescriptionPlaintext, maxGroupDescriptionLen, "descriptionPlaintext", true)
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if req.NamePlaintext != "" || req.DescriptionPlaintext != "" {
			WriteError(w, http.StatusBadRequest, "namePlaintext/descriptionPlaintext: must not be set for a private group")
			return
		}
		nc, err := decodeGroupCiphertext(req.NameCiphertext, "nameCiphertext")
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		nameCiphertext = &nc
		dc, err := decodeGroupCiphertext(req.DescriptionCiphertext, "descriptionCiphertext")
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		descriptionCiphertext = &dc
	}

	groupKeyWrapped, err := decodeWrappedKey(req.GroupKeyWrapped)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "groupKeyWrapped: "+err.Error())
		return
	}

	trustAnchorSig, err := decodeBase64Field(req.TrustAnchorSignature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "trustAnchorSignature: "+err.Error())
		return
	}
	rootGrantSig, err := decodeBase64Field(req.RootGrantSignature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "rootGrantSignature: "+err.Error())
		return
	}

	// The creator's signing key is read from their OWN session-authenticated
	// PROFILE, never trusted from the request body -- there is no field for
	// it. This is what makes the two Verify calls below mean anything: a
	// signature verified against a key the caller sent would only prove the
	// caller controls whatever key it feels like sending, which is no
	// authentication of "the key that was current at group creation" at all.
	// See DESIGN.md, "Pinning the key... matters because... anchoring on the
	// uuid alone would still let the server choose."
	creator, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not create group")
		return
	}

	groupID := req.GroupID

	anchorPayload := crypto.TrustAnchorPayload(userID, creator.SigningPublicKey, groupID)
	if !crypto.Verify(creator.SigningPublicKey, crypto.ContextTrustAnchor, anchorPayload, trustAnchorSig) {
		WriteError(w, http.StatusBadRequest, "trustAnchorSignature: does not verify against the caller's current signing key")
		return
	}

	// RootGrantSortKey is the grant's own address, now part of what
	// RoleGrantPayload signs (see that function's own doc comment for why)
	// -- validated for shape (idgen.ValidGrantSortKey, the same "client
	// decides, server checks the shape" split GroupID gets) and for a day
	// within clock-skew tolerance of now, so a grant cannot be backdated or
	// postdated into a day the chain walk would resolve against the wrong
	// superseded signing key.
	day, ok := idgen.ValidGrantSortKey(req.RootGrantSortKey, userID)
	if !ok {
		WriteError(w, http.StatusBadRequest, "rootGrantSortKey: must be a well-formed GRANT# sort key for the caller's own uuid")
		return
	}
	if skew := time.Since(day.UTC()); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteError(w, http.StatusBadRequest, "rootGrantSortKey: day is not within tolerance of the current UTC day")
		return
	}
	rootGrantSortKey := req.RootGrantSortKey

	// The root grant has no predecessor to reference (models.RoleGrant's own
	// doc comment) -- grantorGrantRef is the empty string here, never a
	// caller-supplied value, since the caller cannot reference a grant that
	// does not yet exist.
	grantPayload := crypto.RoleGrantPayload(groupID, userID, models.RoleAdmin, rootGrantSortKey, "")
	if !crypto.Verify(creator.SigningPublicKey, crypto.ContextRoleGrant, grantPayload, rootGrantSig) {
		WriteError(w, http.StatusBadRequest, "rootGrantSignature: does not verify against the caller's current signing key")
		return
	}

	in := db.CreateGroupInput{
		GroupID: groupID,

		CreatorUserID:           userID,
		CreatorSigningPublicKey: creator.SigningPublicKey,
		TrustAnchorSignature:    trustAnchorSig,

		Visibility: req.Visibility,

		NamePlaintext:         namePlaintext,
		DescriptionPlaintext:  descriptionPlaintext,
		NameCiphertext:        nameCiphertext,
		DescriptionCiphertext: descriptionCiphertext,

		RevocationMode: req.RevocationMode,
		ExpirationDays: expirationDays,

		GenerationKeyWrapped: groupKeyWrapped,

		RootGrantSortKey:   rootGrantSortKey,
		RootGrantSignature: rootGrantSig,
	}

	// storedRootGrantSortKey is what actually got written -- rootGrantSortKey
	// on a fresh create, but the ORIGINAL attempt's key on a lost-response
	// retry (db.CreateGroup's own doc comment): the client re-signs a brand
	// new grantSortKey on every attempt including a resumed one, so echoing
	// back rootGrantSortKey here on a retry would hand out an address
	// nothing was ever written under (PR #142 round 2 review).
	storedRootGrantSortKey, err := h.db.CreateGroup(r.Context(), in)
	if err != nil {
		if errors.Is(err, db.ErrGroupIDTaken) {
			// db.CreateGroup already checked (db.isOwnGroupCreation) whether
			// this is the caller's own earlier, successful call being
			// resent after a lost response, and returned nil instead of
			// this error if so -- see that function's own doc comment.
			// Reaching here means it wasn't: a genuine collision with a
			// different group (someone else's, or this caller's own
			// resend with regenerated signed material), so the client must
			// generate a new groupId and resubmit, not retry this exact
			// request unchanged.
			WriteErrorWithCode(w, http.StatusConflict, "groupId is taken", "group_id_taken")
			return
		}
		WriteError(w, http.StatusInternalServerError, "could not create group")
		return
	}

	WriteJSON(w, http.StatusCreated, createGroupResponse{
		GroupID:          groupID,
		RootGrantSortKey: storedRootGrantSortKey,
	})
}

// ed25519SignatureSize is Ed25519's fixed signature width -- named here for
// the same reason x25519PublicKeySize is named in register.go rather than
// left as a bare 64, since crypto/ed25519 has no exported constant this
// package already imports under a shorter name.
const ed25519SignatureSize = 64

// inviteMACSize is HMAC-SHA256's fixed output width -- crypto.ComputeInviteMAC's
// return length, named for the same reason ed25519SignatureSize is.
const inviteMACSize = 32

// wrappedGroupKeyCiphertextSize is the exact byte width of an ECIES-wrapped
// group key's ciphertext: crypto.KeySize (32, the group key being wrapped)
// plus AES-GCM's 16-byte authentication tag, always exactly 48 bytes for a
// well-formed wrap -- there is no variable-length plaintext here the way a
// group's name or description ciphertext has (maxGroupCiphertextLen's own
// reasoning). An exact check catches a client that wrapped the wrong thing
// (PR #142 review), the same reasoning ephemeralPub and nonce already get
// exact-length checks for in decodeWrappedKey.
const wrappedGroupKeyCiphertextSize = crypto.KeySize + 16

// validateGroupText enforces a plaintext public-group field's length bound.
// allowEmpty is false for the name (a public group must be named something)
// and true for the description (optional). A whitespace-only value is
// rejected the same as an empty one when allowEmpty is false (PR #142
// review): unlike the description, the name becomes a GSI1 directory entry
// (db.CreateGroup's own GSI1SK write) that every visitor to the public
// directory sees, so "   " passing this check would surface as a listed
// group with no visible name.
func validateGroupText(s string, maxLen int, field string, allowEmpty bool) (string, error) {
	if strings.TrimSpace(s) == "" && !allowEmpty {
		return "", fieldError(field + " is required for a public group")
	}
	if len(s) > maxLen {
		return "", fieldError(field + " exceeds the maximum allowed length")
	}
	return s, nil
}

// wrappedBlobEmpty reports whether b is the zero value -- both fields
// unset, meaning the client never populated this wrappedBlob at all. Used
// to reject a public group's request carrying a private group's
// nameCiphertext/descriptionCiphertext fields (or vice versa): a
// well-formed wrappedBlob has both Nonce and Ciphertext non-empty, so
// either one being non-empty here means the client sent something for the
// wrong visibility, not that it left the field out.
func wrappedBlobEmpty(b wrappedBlob) bool {
	return b.Nonce == "" && b.Ciphertext == ""
}

// decodeGroupCiphertext decodes a private group's encrypted name or
// description field, wrapping decodeWrappedBlob's error with the field name
// the same way every other per-field validation in this package does.
func decodeGroupCiphertext(b wrappedBlob, field string) (models.WrappedBlob, error) {
	decoded, err := decodeWrappedBlob(b)
	if err != nil {
		return models.WrappedBlob{}, fieldError(field + ": " + err.Error())
	}
	if len(decoded.Ciphertext) > maxGroupCiphertextLen {
		return models.WrappedBlob{}, fieldError(field + ": ciphertext exceeds the maximum allowed length")
	}
	return decoded, nil
}

// wrappedKey is the wire shape of an X25519-ECIES wrap (crypto.Wrapped) --
// the ephemeralPub field wrappedBlob does not carry, needed to ever unwrap
// it again. See models.WrappedKey's own doc comment.
type wrappedKey struct {
	EphemeralPub string `json:"ephemeralPub"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

// decodeWrappedKey decodes an ECIES-wrapped field, the models.WrappedKey
// counterpart of decodeWrappedBlob. ephemeralPub is validated to exactly
// x25519PublicKeySize, matching every other X25519 public key field this
// package decodes (e.g. registerRequest.WrappingPublicKey).
func decodeWrappedKey(k wrappedKey) (models.WrappedKey, error) {
	ephemeralPub, err := decodeBase64Field(k.EphemeralPub, x25519PublicKeySize, x25519PublicKeySize)
	if err != nil {
		return models.WrappedKey{}, fieldError("ephemeralPub: " + err.Error())
	}
	nonce, err := decodeBase64Field(k.Nonce, crypto.NonceSize, crypto.NonceSize)
	if err != nil {
		return models.WrappedKey{}, fieldError("nonce: " + err.Error())
	}
	ciphertext, err := decodeBase64Field(k.Ciphertext, wrappedGroupKeyCiphertextSize, wrappedGroupKeyCiphertextSize)
	if err != nil {
		return models.WrappedKey{}, fieldError("ciphertext: " + err.Error())
	}
	return models.WrappedKey{EphemeralPub: ephemeralPub, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// encodeWrappedBlob is decodeWrappedBlob's inverse -- issue #35 is the
// first endpoint that SENDS a WrappedBlob to the client rather than only
// ever receiving one, so this direction did not exist before it.
func encodeWrappedBlob(b models.WrappedBlob) wrappedBlob {
	return wrappedBlob{
		Nonce:      base64.StdEncoding.EncodeToString(b.Nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(b.Ciphertext),
	}
}

// encodeWrappedKey is decodeWrappedKey's inverse, for the same reason
// encodeWrappedBlob exists: issue #35 sends a member's own WrappedGroupKey
// back to them so their browser can unwrap it, the first outbound use of
// this shape.
func encodeWrappedKey(k models.WrappedKey) wrappedKey {
	return wrappedKey{
		EphemeralPub: base64.StdEncoding.EncodeToString(k.EphemeralPub),
		Nonce:        base64.StdEncoding.EncodeToString(k.Nonce),
		Ciphertext:   base64.StdEncoding.EncodeToString(k.Ciphertext),
	}
}

// groupListEntry is one group in GET /api/groups's response -- issue #35.
// Exactly one of the two field pairs is populated, matching Visibility, the
// same split createGroupRequest's own doc comment describes for the
// opposite (write) direction: NamePlaintext/DescriptionPlaintext for a
// public group, NameCiphertext/DescriptionCiphertext (plus the member's own
// WrappedGroupKey, needed to ever decrypt them) for a private one. There is
// no unread count field -- see listGroups' own doc comment for why this
// issue ships without one.
type groupListEntry struct {
	GroupID    string `json:"groupId"`
	Visibility string `json:"visibility"`
	Role       string `json:"role"`
	Generation int64  `json:"generation"`
	// NameGeneration is the key generation the private name/description
	// ciphertexts are encrypted under. It is NOT the member's Generation:
	// rotation does not re-encrypt the name (docs/DESIGN.md), so once
	// rotation exists the two diverge, and the name's AAD must be built
	// from this value.
	NameGeneration int64 `json:"nameGeneration"`

	NamePlaintext        string `json:"namePlaintext,omitempty"`
	DescriptionPlaintext string `json:"descriptionPlaintext,omitempty"`

	NameCiphertext        *wrappedBlob `json:"nameCiphertext,omitempty"`
	DescriptionCiphertext *wrappedBlob `json:"descriptionCiphertext,omitempty"`
	WrappedGroupKey       *wrappedKey  `json:"wrappedGroupKey,omitempty"`
}

// listGroupsResponse is the wire shape of GET /api/groups.
type listGroupsResponse struct {
	Groups []groupListEntry `json:"groups"`
}

// listGroups implements GET /api/groups -- issue #35. Authenticated by
// requireSession, same as createGroup.
//
// This is db.ListGroups' one GSI1 Query (the caller's own memberships) plus
// one META GetItem-equivalent per group (db.ListGroups' own BatchGetItem
// fan-out), exactly the read shape docs/DESIGN.md names as the product's
// hottest path: "Rendering a user's group list is... one GSI1 Query...
// plus one GetItem per group." This handler does no decryption of its
// own -- a private group's name and description are ciphertext under the
// group key, which only the caller's own browser can unwrap (its wrapping
// private key never leaves the crypto worker, per worker.ts's own doc
// comment), so this response hands back exactly the ciphertext and the
// caller's own WrappedGroupKey and nothing more.
//
// Deliberately has NO unread-count field, unlike issue #35's own one-line
// description ("returning groups with unread counts"). Investigating this
// issue found that the only unread mechanism docs/DESIGN.md describes
// depends on NOTIF# items (a notification's `read` flag), and nothing in
// that chain exists yet: no posts (#42-46), no comments, no notifications
// (M7+). Shipping a fabricated or always-zero count here would be worse
// than omitting the field -- a client cannot tell "genuinely zero unread"
// from "this deployment hasn't built unread tracking yet." Filed as a
// separate follow-up (#145) once that infrastructure exists; adding it
// later is additive to this response shape, not a breaking change.
func (h *Handler) listGroups(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	memberships, groups, err := h.db.ListGroups(r.Context(), userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not list groups")
		return
	}

	// db.ListGroups already drops a membership whose META vanished (a state
	// this schema does not otherwise produce -- see that function's own doc
	// comment) rather than erroring the whole call, so memberships and
	// groups are the same length here, in matching order, safe to zip by
	// index rather than re-joining by id a second time.
	entries := make([]groupListEntry, 0, len(memberships))
	for i, m := range memberships {
		g := groups[i]
		entry := groupListEntry{
			GroupID:        strings.TrimPrefix(m.PK, "GROUP#"),
			Visibility:     g.Visibility,
			Role:           m.Role,
			Generation:     m.Generation,
			NameGeneration: g.NameGeneration,
		}
		if g.Visibility == models.VisibilityPublic {
			entry.NamePlaintext = g.NamePlaintext
			entry.DescriptionPlaintext = g.DescriptionPlaintext
		} else {
			if g.NameCiphertext != nil {
				nc := encodeWrappedBlob(*g.NameCiphertext)
				entry.NameCiphertext = &nc
			}
			if g.DescriptionCiphertext != nil {
				dc := encodeWrappedBlob(*g.DescriptionCiphertext)
				entry.DescriptionCiphertext = &dc
			}
			wk := encodeWrappedKey(m.WrappedGroupKey)
			entry.WrappedGroupKey = &wk
		}
		entries = append(entries, entry)
	}

	WriteJSON(w, http.StatusOK, listGroupsResponse{Groups: entries})
}

// maxExpirationDays bounds a group's expiration policy from above --
// generous relative to any real retention policy (about 10 years), but
// enough to matter once posts start computing a TTL as
// days * 86400 seconds from now (PR #142 review): a huge, effectively
// unbounded int64 here would risk overflowing that arithmetic once #34's
// sibling issues actually consume ExpirationDays this way.
const maxExpirationDays = 3650

// errExpirationOffNotAllowed and errExpirationDaysInvalid are
// validateExpirationDays' failure modes.
var (
	errExpirationOffNotAllowed = fieldError("expirationDays: this deployment does not allow groups to disable expiration (expirationDays must be positive)")
	errExpirationDaysInvalid   = fieldError("expirationDays: must be zero (never expire) or a positive number of days, up to 3650")
)

// validateExpirationDays checks a group's requested expiration policy.
// Zero means "never expire" (models.Group.ExpirationDays' own doc comment)
// and is only accepted when allowOff (config.Config.AllowGroupExpirationOff)
// permits it -- a deployment may forbid disabling the one forward-secrecy
// mechanism that works at any group size, per docs/DESIGN.md, "Message
// expiration." A negative value is never valid; there is no meaning for it.
func validateExpirationDays(days int64, allowOff bool) (int64, error) {
	if days < 0 || days > maxExpirationDays {
		return 0, errExpirationDaysInvalid
	}
	if days == 0 {
		if !allowOff {
			return 0, errExpirationOffNotAllowed
		}
		return 0, nil
	}
	return days, nil
}

// groupDetailResponse is the wire shape of GET /api/groups/{groupId} -- issue
// #36. It is a groupListEntry plus the settings a detail screen shows:
// revocation mode (always displayed, never editable), the expiration policy,
// and the Version and NameGeneration a later PUT must echo back. Role is
// empty for a non-member viewing a public group, who also gets no
// WrappedGroupKey.
type groupDetailResponse struct {
	groupListEntry
	RevocationMode string `json:"revocationMode"`
	ExpirationDays int64  `json:"expirationDays"`
	Version        int64  `json:"version"`
}

// groupNotFound is the one response for "no such group" and "a private group
// you are not in" alike: docs/DESIGN.md wants a private group invisible to
// non-members, which a distinct 403 would betray.
func groupNotFound(w http.ResponseWriter) {
	WriteError(w, http.StatusNotFound, "group not found")
}

// getGroup implements GET /api/groups/{groupId} -- issue #36. Members of any
// group see it; anyone signed in sees a public group; a private group is 404
// to non-members. The response carries no CreatedAt (issue #147) and no
// roster (issue #37 is members-only, always).
func (h *Handler) getGroup(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}

	// Both reads happen before either 404 branch: a nonexistent group and a
	// private group the caller is not in must cost the same two round trips,
	// or latency alone would reveal which group ids exist.
	g, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not load group")
		return
	}
	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not load group")
		return
	}
	if g == nil || (m == nil && g.Visibility != models.VisibilityPublic) {
		groupNotFound(w)
		return
	}

	entry := groupListEntry{
		GroupID:        groupID,
		Visibility:     g.Visibility,
		NameGeneration: g.NameGeneration,
	}
	if m != nil {
		entry.Role = m.Role
		entry.Generation = m.Generation
	}
	if g.Visibility == models.VisibilityPublic {
		entry.NamePlaintext = g.NamePlaintext
		entry.DescriptionPlaintext = g.DescriptionPlaintext
	} else {
		if g.NameCiphertext != nil {
			nc := encodeWrappedBlob(*g.NameCiphertext)
			entry.NameCiphertext = &nc
		}
		if g.DescriptionCiphertext != nil {
			dc := encodeWrappedBlob(*g.DescriptionCiphertext)
			entry.DescriptionCiphertext = &dc
		}
		wk := encodeWrappedKey(m.WrappedGroupKey)
		entry.WrappedGroupKey = &wk
	}

	WriteJSON(w, http.StatusOK, groupDetailResponse{
		groupListEntry: entry,
		RevocationMode: g.RevocationMode,
		ExpirationDays: g.ExpirationDays,
		Version:        g.Version,
	})
}

const maxUpdateGroupBodyBytes = 16 * 1024

// updateGroupRequest is the wire shape of PUT /api/groups/{groupId}: a full
// replacement of name, description and expiration policy, so there is no
// partial-update ambiguity. Revocation mode and visibility are absent on
// purpose. Version must be the value GET returned; a stale one is a 409.
// The same one-pair-per-visibility rule as createGroupRequest applies, and a
// private group's NameGeneration is the generation the ciphertexts were
// encrypted under (crypto.GroupNameAAD).
type updateGroupRequest struct {
	Version int64 `json:"version"`

	NamePlaintext         string      `json:"namePlaintext,omitempty"`
	DescriptionPlaintext  string      `json:"descriptionPlaintext,omitempty"`
	NameCiphertext        wrappedBlob `json:"nameCiphertext,omitempty"`
	DescriptionCiphertext wrappedBlob `json:"descriptionCiphertext,omitempty"`
	NameGeneration        int64       `json:"nameGeneration"`

	ExpirationDays int64 `json:"expirationDays"`
}

// updateGroup implements PUT /api/groups/{groupId} -- issue #36. Admin only,
// judged from the caller's own MEMBER# row (signed role grants are #37's
// concern); db.UpdateGroupSettings re-checks Admin inside its transaction so
// a concurrent demotion cannot slip through the gap.
func (h *Handler) updateGroup(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	groupID := r.PathValue("groupId")
	if !idgen.ValidUUID(groupID) {
		groupNotFound(w)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxUpdateGroupBodyBytes)
	var req updateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, http.StatusBadRequest, "malformed request body")
		return
	}

	// Both reads before either 404 branch -- see getGroup.
	g, err := h.db.GetGroup(r.Context(), groupID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not update group")
		return
	}
	m, err := h.db.GetMembership(r.Context(), groupID, userID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "could not update group")
		return
	}
	if g == nil || (m == nil && g.Visibility != models.VisibilityPublic) {
		groupNotFound(w)
		return
	}
	if m == nil || m.Role != models.RoleAdmin {
		WriteError(w, http.StatusForbidden, "only a group admin can edit group settings")
		return
	}
	if g.GroupType == "dm" {
		WriteError(w, http.StatusBadRequest, "a direct message has no editable settings")
		return
	}

	if req.Version < 0 {
		WriteError(w, http.StatusBadRequest, "version: must not be negative")
		return
	}
	expirationDays, err := validateExpirationDays(req.ExpirationDays, h.cfg.AllowGroupExpirationOff)
	if err != nil {
		WriteError(w, http.StatusBadRequest, err.Error())
		return
	}

	in := db.UpdateGroupSettingsInput{
		GroupID:         groupID,
		AdminUserID:     userID,
		Visibility:      g.Visibility,
		ExpectedVersion: req.Version,
		ExpirationDays:  expirationDays,
	}
	if g.Visibility == models.VisibilityPublic {
		if !wrappedBlobEmpty(req.NameCiphertext) || !wrappedBlobEmpty(req.DescriptionCiphertext) || req.NameGeneration != 0 {
			WriteError(w, http.StatusBadRequest, "nameCiphertext/descriptionCiphertext/nameGeneration: must not be set for a public group")
			return
		}
		in.NamePlaintext, err = validateGroupText(req.NamePlaintext, maxGroupNameLen, "namePlaintext", false)
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.DescriptionPlaintext, err = validateGroupText(req.DescriptionPlaintext, maxGroupDescriptionLen, "descriptionPlaintext", true)
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		if req.NamePlaintext != "" || req.DescriptionPlaintext != "" {
			WriteError(w, http.StatusBadRequest, "namePlaintext/descriptionPlaintext: must not be set for a private group")
			return
		}
		// The admin can only have encrypted under a generation they hold,
		// and their membership records the newest one. The stored
		// generation must never move backward.
		if req.NameGeneration != m.Generation || req.NameGeneration < g.NameGeneration {
			WriteError(w, http.StatusBadRequest, "nameGeneration: must be the caller's current key generation")
			return
		}
		nc, err := decodeGroupCiphertext(req.NameCiphertext, "nameCiphertext")
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		dc, err := decodeGroupCiphertext(req.DescriptionCiphertext, "descriptionCiphertext")
		if err != nil {
			WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		in.NameCiphertext, in.DescriptionCiphertext, in.NameGeneration = &nc, &dc, req.NameGeneration
	}

	if err := h.db.UpdateGroupSettings(r.Context(), in); err != nil {
		switch {
		case errors.Is(err, db.ErrGroupVersionConflict):
			WriteErrorWithCode(w, http.StatusConflict, "the group changed since you loaded it; reload and retry", "version_conflict")
		case errors.Is(err, db.ErrNotGroupAdmin):
			WriteError(w, http.StatusForbidden, "only a group admin can edit group settings")
		default:
			WriteError(w, http.StatusInternalServerError, "could not update group")
		}
		return
	}
	WriteJSON(w, http.StatusOK, map[string]int64{"version": req.Version + 1})
}
