package handlers

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
	"github.com/pwntato/undergroundbb/internal/idgen"
	"github.com/pwntato/undergroundbb/internal/models"
)

// Direct messages (#73). A DM is created through POST /api/groups (one code path: the group, the
// sender's membership and root grant are the same rows), with a "dm" object carrying what is
// specific to it. See docs/DESIGN.md, "Direct messages".

// dmRequestBody is the "dm" field of createGroupRequest.
type dmRequestBody struct {
	RecipientUserID string `json:"recipientUserId"`
	// RequestID is a fresh UUID the sender picks; it is signed into the admission (the invite-id slot).
	RequestID string `json:"requestId"`
	// WrappedGroupKey is the Generation 0 group key wrapped to the recipient's X25519 key.
	WrappedGroupKey wrappedKey `json:"wrappedGroupKey"`
	// Admission is the sender's signed admission of the recipient, over the recipient's keys as
	// the server supplied them (the TOFU moment), with the sender's root grant as its grant ref
	// and generation 0.
	Admission struct {
		Day       string `json:"day"`
		Signature string `json:"signature"`
	} `json:"admission"`
}

// dmWritable writes a 409 and returns false when group is a DM that has lost a member: it is
// read-only then. An ordinary group is always writable.
func (h *Handler) dmWritable(w http.ResponseWriter, r *http.Request, group *models.Group) bool {
	if group == nil || group.GroupType != "dm" {
		return true
	}
	ok, err := h.db.DMWritable(r.Context(), strings.TrimPrefix(group.PK, "GROUP#"))
	if err != nil {
		WriteInternalError(w, r, err, "could not check the direct message")
		return false
	}
	if !ok {
		WriteErrorWithCode(w, http.StatusConflict, "the other person has left this conversation; it is read-only", "dm_read_only")
		return false
	}
	return true
}

// dmCreateInput validates the DM part of a create-group request and returns the db input. It
// writes the error response itself and returns ok=false on failure.
func (h *Handler) dmCreateInput(w http.ResponseWriter, r *http.Request, req *createGroupRequest, userID string, creatorSigningKey []byte) (*db.CreateDMInput, bool) {
	body := req.DM
	if req.Visibility != models.VisibilityPrivate {
		WriteError(w, http.StatusBadRequest, "visibility: a direct message is private")
		return nil, false
	}
	if req.RevocationMode != models.RevocationOpen {
		WriteError(w, http.StatusBadRequest, "revocationMode: a direct message is \"open\"")
		return nil, false
	}
	if req.NamePlaintext != "" || req.DescriptionPlaintext != "" || !wrappedBlobEmpty(req.NameCiphertext) || !wrappedBlobEmpty(req.DescriptionCiphertext) {
		WriteError(w, http.StatusBadRequest, "name and description: a direct message has none")
		return nil, false
	}
	if !idgen.ValidUUID(body.RecipientUserID) || !idgen.ValidUUID(body.RequestID) {
		WriteError(w, http.StatusBadRequest, "dm.recipientUserId and dm.requestId: must be well-formed, lowercase UUIDv4s")
		return nil, false
	}
	if body.RecipientUserID == userID {
		WriteError(w, http.StatusBadRequest, "dm.recipientUserId: you cannot message yourself")
		return nil, false
	}
	wrapped, err := decodeWrappedKey(body.WrappedGroupKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "dm.wrappedGroupKey: "+err.Error())
		return nil, false
	}
	sig, err := decodeBase64Field(body.Admission.Signature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "dm.admission.signature: "+err.Error())
		return nil, false
	}
	day, err := time.Parse("2006-01-02", body.Admission.Day)
	if err != nil || day.Format("2006-01-02") != body.Admission.Day {
		WriteError(w, http.StatusBadRequest, "dm.admission.day: must be a UTC date, YYYY-MM-DD")
		return nil, false
	}
	if skew := time.Since(day.UTC()); skew < -grantDaySkewTolerance || skew > 24*time.Hour+grantDaySkewTolerance {
		WriteErrorWithCode(w, http.StatusBadRequest, "dm.admission.day: not within tolerance of the current UTC day", "clock_skew")
		return nil, false
	}
	recipient, err := h.db.GetUserByID(r.Context(), body.RecipientUserID)
	if err != nil && !errors.Is(err, db.ErrUserNotFound) {
		WriteInternalError(w, r, err, "could not create the direct message")
		return nil, false
	}
	if recipient == nil || recipient.DeletedAt != "" {
		WriteErrorWithCode(w, http.StatusNotFound, "no such user", "recipient_not_found")
		return nil, false
	}
	// The admission signs the recipient's keys exactly as the server holds them now: the sender's
	// client showed the fingerprint of these, and the recipient's client checks them again.
	payload := crypto.AdmissionPayload(req.GroupID, userID, body.RecipientUserID, recipient.SigningPublicKey, recipient.WrappingPublicKey,
		body.RequestID, req.RootGrantSortKey, body.Admission.Day, 0)
	if !crypto.Verify(creatorSigningKey, crypto.ContextAdmission, payload, sig) {
		WriteErrorWithCode(w, http.StatusBadRequest, "dm.admission.signature: does not verify against the caller's current signing key", "bad_signature")
		return nil, false
	}
	pending, err := h.db.CountPendingDMs(r.Context(), userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not create the direct message")
		return nil, false
	}
	if pending >= db.MaxPendingDMsPerSender {
		WriteErrorWithCode(w, http.StatusTooManyRequests, "too many direct messages are waiting for an answer; wait for replies or withdraw some", "too_many_pending_dms")
		return nil, false
	}
	return &db.CreateDMInput{
		RecipientUserID:   body.RecipientUserID,
		RequestID:         body.RequestID,
		RecipientEd25519:  recipient.SigningPublicKey,
		RecipientX25519:   recipient.WrappingPublicKey,
		RecipientKeyEpoch: recipient.KeyEpoch,
		WrappedGroupKey:   wrapped,
		AdmissionDay:      body.Admission.Day,
		AdmissionSig:      sig,
	}, true
}

// writeDMCreateError maps the DM errors of db.CreateGroup. It returns false for an error it does
// not know.
func writeDMCreateError(w http.ResponseWriter, err error) bool {
	var exists *db.DMExistsError
	var cooling *db.DMCoolingOffError
	switch {
	case errors.As(err, &exists):
		WriteJSON(w, http.StatusConflict, map[string]string{
			"error": "you already have a conversation with this person", "code": "dm_exists", "groupId": exists.GroupID,
		})
	case errors.As(err, &cooling):
		WriteErrorWithCode(w, http.StatusConflict, "this person declined; you can try again after "+cooling.Until.Format("2006-01-02"), "dm_cooling_off")
	case errors.Is(err, db.ErrDMRecipientGone):
		WriteErrorWithCode(w, http.StatusGone, "that account no longer exists", "recipient_deleted")
	default:
		return false
	}
	return true
}

type dmIncomingEntry struct {
	GroupID           string     `json:"groupId"`
	SenderUserID      string     `json:"senderUserId"`
	RequestID         string     `json:"requestId"`
	RecipientEd25519  string     `json:"recipientEd25519PublicKey"`
	RecipientX25519   string     `json:"recipientX25519PublicKey"`
	WrappedGroupKey   wrappedKey `json:"wrappedGroupKey"`
	AdmissionDay      string     `json:"admissionDay"`
	AdmissionGrantRef string     `json:"admissionGrantRef"`
	AdmissionSig      string     `json:"admissionSignature"`
}

func dmIncomingOf(q *models.DMRequest) dmIncomingEntry {
	return dmIncomingEntry{
		GroupID:          q.GroupID,
		SenderUserID:     q.SenderUserID,
		RequestID:        q.RequestID,
		RecipientEd25519: encodeBase64(q.RecipientEd25519),
		RecipientX25519:  encodeBase64(q.RecipientX25519),
		WrappedGroupKey: wrappedKey{
			EphemeralPub: encodeBase64(q.WrappedGroupKey.EphemeralPub),
			Nonce:        encodeBase64(q.WrappedGroupKey.Nonce),
			Ciphertext:   encodeBase64(q.WrappedGroupKey.Ciphertext),
		},
		AdmissionDay:      q.AdmissionDay,
		AdmissionGrantRef: q.AdmissionGrantRef,
		AdmissionSig:      encodeBase64(q.AdmissionSig),
	}
}

// listIncomingDMs implements GET /api/dms/incoming: the DMs waiting for the caller to open.
func (h *Handler) listIncomingDMs(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	reqs, err := h.db.ListIncomingDMs(r.Context(), userID, 100)
	if err != nil {
		WriteInternalError(w, r, err, "could not list direct messages")
		return
	}
	out := make([]dmIncomingEntry, 0, len(reqs))
	for i := range reqs {
		out = append(out, dmIncomingOf(&reqs[i]))
	}
	WriteJSON(w, http.StatusOK, map[string][]dmIncomingEntry{"dms": out})
}

// pendingDM loads the caller's slot for the group and checks the request id the caller verified.
func (h *Handler) pendingDM(w http.ResponseWriter, r *http.Request, userID string) (*models.DMRequest, string, bool) {
	groupID := r.PathValue("groupId")
	requestID := r.URL.Query().Get("requestId")
	if !idgen.ValidUUID(groupID) || !idgen.ValidUUID(requestID) {
		WriteError(w, http.StatusBadRequest, "groupId and requestId: must be well-formed, lowercase UUIDv4s")
		return nil, "", false
	}
	req, err := h.db.GetDMRequest(r.Context(), groupID, userID)
	if err != nil {
		WriteInternalError(w, r, err, "could not load the direct message")
		return nil, "", false
	}
	if req == nil {
		WriteError(w, http.StatusNotFound, "no such pending direct message")
		return nil, "", false
	}
	if req.RequestID != requestID {
		WriteErrorWithCode(w, http.StatusConflict, "this conversation changed since you loaded it; reload", "request_changed")
		return nil, "", false
	}
	return req, db.DMPairPK(req.SenderUserID, userID), true
}

// acceptDM implements POST /api/dms/{groupId}/accept?requestId=: the recipient opens the
// conversation. Their client has already verified the sender's admission and shown the
// fingerprint; this writes their membership.
func (h *Handler) acceptDM(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	req, pairPK, ok := h.pendingDM(w, r, userID)
	if !ok {
		return
	}
	// The wrap is to the keys the sender signed; if the caller has rotated since, the membership
	// would be dormant on arrival, so refuse and let the sender start again.
	self, err := h.db.GetUserByIDConsistent(r.Context(), userID)
	if err != nil || self == nil {
		WriteInternalError(w, r, err, "could not open the direct message")
		return
	}
	if string(self.SigningPublicKey) != string(req.RecipientEd25519) || string(self.WrappingPublicKey) != string(req.RecipientX25519) {
		WriteErrorWithCode(w, http.StatusConflict, "your keys changed since this message was sent; ask them to send it again", "keys_changed")
		return
	}
	switch err := h.db.AcceptDM(r.Context(), req, pairPK); {
	case err == nil:
		WriteJSON(w, http.StatusOK, map[string]string{"status": "accepted", "groupId": req.GroupID})
	case errors.Is(err, db.ErrDMNotFound):
		WriteError(w, http.StatusNotFound, "no such pending direct message")
	case errors.Is(err, db.ErrAlreadyMember):
		WriteErrorWithCode(w, http.StatusConflict, "you are already in this conversation", "already_member")
	case errors.Is(err, db.ErrWrapEpochStale):
		WriteErrorWithCode(w, http.StatusConflict, "your keys changed while this was opened; reload and try again", "keys_changed")
	default:
		WriteInternalError(w, r, err, "could not open the direct message")
	}
}

// declineDM implements POST /api/dms/{groupId}/decline?requestId=: the recipient refuses. The
// conversation is deleted and the sender is kept out for db.DMDeclineCoolOff.
func (h *Handler) declineDM(w http.ResponseWriter, r *http.Request) {
	userID, ok := sessionUserID(r)
	if !ok {
		WriteError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	req, pairPK, ok := h.pendingDM(w, r, userID)
	if !ok {
		return
	}
	switch err := h.db.DeclineDM(r.Context(), req, pairPK); {
	case err == nil:
		WriteJSON(w, http.StatusOK, map[string]string{"status": "declined"})
	case errors.Is(err, db.ErrDMNotFound):
		WriteError(w, http.StatusNotFound, "no such pending direct message")
	default:
		WriteInternalError(w, r, err, "could not decline the direct message")
	}
}
