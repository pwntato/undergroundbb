package handlers

import (
	"net/http"

	"github.com/pwntato/undergroundbb/internal/crypto"
	"github.com/pwntato/undergroundbb/internal/db"
)

// wrapRecordFields are the optional fields a wrap request carries to sign who
// wrapped (#280, docs/DESIGN.md, "Who wrapped a member's entry"). Both or
// neither: a client from before this existed sends neither and its wraps read
// as having no signed record. Embedded in each request so the JSON stays flat.
type wrapRecordFields struct {
	WrapSignature string `json:"wrapSignature,omitempty"`
	WrapDay       string `json:"wrapDay,omitempty"`
}

// wrapRecordProblem is a refusal of the fields, ready to write.
type wrapRecordProblem struct {
	message string
	code    string
}

func (p *wrapRecordProblem) write(w http.ResponseWriter) {
	if p.code != "" {
		WriteErrorWithCode(w, http.StatusBadRequest, p.message, p.code)
		return
	}
	WriteError(w, http.StatusBadRequest, p.message)
}

// wrapRecord checks the fields against the entry this request is about to
// write and returns the record to store, nil when the client sent none. The
// reason is fixed by the endpoint, never read from the body, and the payload is
// built from the generation and member key epoch the request itself writes, so
// a signature made for another wrap, member, group, reason or day does not
// verify. The signer is the caller's current signing key, read strongly
// consistent like every other signed start. The error is an internal one.
func (h *Handler) wrapRecord(r *http.Request, f wrapRecordFields, groupID, wrapperID, memberID string, generation int64, keyEpoch uint64, reason string) (*db.WrapRecord, *wrapRecordProblem, error) {
	if f.WrapSignature == "" && f.WrapDay == "" {
		return nil, nil, nil
	}
	if f.WrapSignature == "" || f.WrapDay == "" {
		return nil, &wrapRecordProblem{message: "wrapSignature and wrapDay: send both or neither"}, nil
	}
	if !validSignedDay(f.WrapDay) {
		if signedDayPassed(f.WrapDay) {
			return nil, &wrapRecordProblem{message: "wrapDay: must be today's UTC date (YYYY-MM-DD)", code: "signed_day_stale"}, nil
		}
		return nil, &wrapRecordProblem{message: "wrapDay: must be today's UTC date (YYYY-MM-DD)"}, nil
	}
	sig, err := decodeBase64Field(f.WrapSignature, ed25519SignatureSize, maxSignatureLen)
	if err != nil {
		return nil, &wrapRecordProblem{message: "wrapSignature: " + err.Error(), code: "bad_signature"}, nil
	}
	self, err := h.db.GetUserByIDConsistent(r.Context(), wrapperID)
	if err != nil {
		return nil, nil, err
	}
	payload := crypto.WrapRecordPayload(groupID, wrapperID, memberID, generation, keyEpoch, reason, f.WrapDay)
	if !crypto.Verify(self.SigningPublicKey, crypto.ContextWrapRecord, payload, sig) {
		return nil, &wrapRecordProblem{message: "wrapSignature: does not verify against the caller's current signing key", code: "bad_signature"}, nil
	}
	return &db.WrapRecord{WrapperUserID: wrapperID, Reason: reason, Day: f.WrapDay, Signature: sig}, nil, nil
}
