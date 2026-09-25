package db

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/pwntato/undergroundbb/internal/models"
)

func testRewrapInput(userID string, expectedVersion int64) RewrapCredentialsInput {
	return RewrapCredentialsInput{
		UserID:                    userID,
		ExpectedCredentialVersion: expectedVersion,
		NewCredentialVersion:      expectedVersion + 1,

		Salt:         []byte("new-salt"),
		Argon2Params: models.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1},
		WrappedPrivateKeys: models.WrappedBlob{
			Nonce:      make([]byte, 12),
			Ciphertext: []byte("new-ciphertext"),
		},

		RecoverySalt:         []byte("new-recovery-salt"),
		RecoveryArgon2Params: models.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1},
		RecoveryWrappedPrivateKeys: models.WrappedBlob{
			Nonce:      make([]byte, 12),
			Ciphertext: []byte("new-recovery-ciphertext"),
		},

		RecoveryVerifierSalt:   []byte("new-verifier-salt"),
		RecoveryVerifierParams: models.Argon2Params{MemoryKiB: 19456, Iterations: 2, Parallelism: 1},
		RecoveryVerifier:       []byte("new-verifier"),
	}
}

// TestRewrapCredentialsSuccess covers the happy path: PROFILE and RECOVERY
// are both rewritten, CredentialVersion bumps on both, and the fields not
// touched by a re-wrap (Username, public keys) are left alone -- see
// docs/DESIGN.md, "Changing a password does not change keys."
func TestRewrapCredentialsSuccess(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-rewrap-" + randomSuffix(t)
	username := "rewrapuser-" + randomSuffix(t)
	reg := testRegisterInput(userID, username)
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	in := testRewrapInput(userID, 1)
	if err := c.RewrapCredentials(ctx, in); err != nil {
		t.Fatalf("RewrapCredentials: %v", err)
	}

	user, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+userID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	var profile models.User
	if err := unmarshalItem(user.Item, &profile); err != nil {
		t.Fatalf("unmarshal PROFILE: %v", err)
	}
	if profile.CredentialVersion != 2 {
		t.Errorf("PROFILE CredentialVersion = %d, want 2", profile.CredentialVersion)
	}
	if string(profile.Salt) != string(in.Salt) {
		t.Errorf("PROFILE Salt = %q, want %q", profile.Salt, in.Salt)
	}
	if string(profile.WrappedPrivateKeys.Ciphertext) != string(in.WrappedPrivateKeys.Ciphertext) {
		t.Errorf("PROFILE WrappedPrivateKeys.Ciphertext = %q, want %q", profile.WrappedPrivateKeys.Ciphertext, in.WrappedPrivateKeys.Ciphertext)
	}
	if profile.Argon2Params != in.Argon2Params {
		t.Errorf("PROFILE Argon2Params = %+v, want %+v", profile.Argon2Params, in.Argon2Params)
	}
	// Untouched fields must survive the re-wrap.
	if profile.Username != username {
		t.Errorf("PROFILE Username = %q, want %q (must not change on a credential re-wrap)", profile.Username, username)
	}

	recovery, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+userID, "RECOVERY"))
	if err != nil {
		t.Fatalf("GetItem RECOVERY: %v", err)
	}
	var rec models.Recovery
	if err := unmarshalItem(recovery.Item, &rec); err != nil {
		t.Fatalf("unmarshal RECOVERY: %v", err)
	}
	if rec.CredentialVersion != 2 {
		t.Errorf("RECOVERY CredentialVersion = %d, want 2", rec.CredentialVersion)
	}
	if string(rec.Salt) != string(in.RecoverySalt) {
		t.Errorf("RECOVERY Salt = %q, want %q", rec.Salt, in.RecoverySalt)
	}
	if rec.Argon2Params != in.RecoveryArgon2Params {
		t.Errorf("RECOVERY Argon2Params = %+v, want %+v", rec.Argon2Params, in.RecoveryArgon2Params)
	}
	if rec.VerifierArgon2Params != in.RecoveryVerifierParams {
		t.Errorf("RECOVERY VerifierArgon2Params = %+v, want %+v", rec.VerifierArgon2Params, in.RecoveryVerifierParams)
	}
	if string(rec.Verifier) != string(in.RecoveryVerifier) {
		t.Errorf("RECOVERY Verifier = %q, want %q", rec.Verifier, in.RecoveryVerifier)
	}
	if string(rec.VerifierSalt) != string(in.RecoveryVerifierSalt) {
		t.Errorf("RECOVERY VerifierSalt = %q, want %q", rec.VerifierSalt, in.RecoveryVerifierSalt)
	}
}

// TestRewrapCredentialsStaleVersionFails covers the condition itself: a
// call with a stale ExpectedCredentialVersion must fail with
// ErrCredentialVersionStale rather than silently overwriting a newer
// re-wrap -- docs/DESIGN.md's "the losing writer fails its condition."
func TestRewrapCredentialsStaleVersionFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-rewrap-stale-" + randomSuffix(t)
	reg := testRegisterInput(userID, "rewrapstale-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// First re-wrap succeeds and bumps the version to 2.
	first := testRewrapInput(userID, 1)
	if err := c.RewrapCredentials(ctx, first); err != nil {
		t.Fatalf("first RewrapCredentials: %v", err)
	}

	// Second re-wrap still claims to expect version 1 -- stale.
	second := testRewrapInput(userID, 1)
	err := c.RewrapCredentials(ctx, second)
	if !errors.Is(err, ErrCredentialVersionStale) {
		t.Fatalf("second RewrapCredentials error = %v, want ErrCredentialVersionStale", err)
	}

	// The loser's write must not have landed at all -- PROFILE should still
	// reflect the first re-wrap's values, not a partial application of the
	// second.
	user, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+userID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	var profile models.User
	if err := unmarshalItem(user.Item, &profile); err != nil {
		t.Fatalf("unmarshal PROFILE: %v", err)
	}
	if profile.CredentialVersion != 2 {
		t.Errorf("PROFILE CredentialVersion = %d, want 2 (unchanged by the losing call)", profile.CredentialVersion)
	}
	if string(profile.Salt) != string(first.Salt) {
		t.Errorf("PROFILE Salt = %q, want %q (the first re-wrap's value)", profile.Salt, first.Salt)
	}
}

// TestRewrapCredentialsConcurrentRace is the concurrency analogue of
// TestRegisterUsernameTakenConcurrent, but for the fourth contested write
// docs/DESIGN.md names rather than the third: two concurrent re-wraps for
// the same account must produce exactly one winner and one
// ErrCredentialVersionStale loser, never both succeeding (the lost-update
// docs/DESIGN.md says would leave the user holding a silently dead
// recovery code).
func TestRewrapCredentialsConcurrentRace(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-rewrap-race-" + randomSuffix(t)
	reg := testRegisterInput(userID, "rewraprace-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	a := testRewrapInput(userID, 1)
	a.RecoveryVerifier = []byte("verifier-a")
	b := testRewrapInput(userID, 1)
	b.RecoveryVerifier = []byte("verifier-b")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = c.RewrapCredentials(ctx, a) }()
	go func() { defer wg.Done(); errs[1] = c.RewrapCredentials(ctx, b) }()
	wg.Wait()

	wins, losses := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrCredentialVersionStale):
			losses++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("wins=%d losses=%d, want exactly one winner and one loser", wins, losses)
	}

	// PROFILE and RECOVERY must both reflect the SAME winner -- not one
	// item from A and the other from B, which would reproduce exactly the
	// stale-credential partial state docs/DESIGN.md's contested-write
	// paragraph exists to prevent.
	winnerVerifier := string(a.RecoveryVerifier)
	if errs[0] != nil {
		winnerVerifier = string(b.RecoveryVerifier)
	}
	recovery, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+userID, "RECOVERY"))
	if err != nil {
		t.Fatalf("GetItem RECOVERY: %v", err)
	}
	var rec models.Recovery
	if err := unmarshalItem(recovery.Item, &rec); err != nil {
		t.Fatalf("unmarshal RECOVERY: %v", err)
	}
	if string(rec.Verifier) != winnerVerifier {
		t.Errorf("RECOVERY Verifier = %q, want winner's %q", rec.Verifier, winnerVerifier)
	}
	if rec.CredentialVersion != 2 {
		t.Errorf("RECOVERY CredentialVersion = %d, want 2", rec.CredentialVersion)
	}
}

// TestRewrapCredentialsStoresIdempotencyToken confirms RewrapCredentials
// actually persists IdempotencyToken to RECOVERY's LastRewrapToken when set
// -- the field IsOwnRewrap reads back. Issue #130.
func TestRewrapCredentialsStoresIdempotencyToken(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-rewrap-token-store-" + randomSuffix(t)
	reg := testRegisterInput(userID, "rewraptokenstore-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	in := testRewrapInput(userID, 1)
	in.IdempotencyToken = []byte("token-a-16-bytes")
	if err := c.RewrapCredentials(ctx, in); err != nil {
		t.Fatalf("RewrapCredentials: %v", err)
	}

	recovery, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+userID, "RECOVERY"))
	if err != nil {
		t.Fatalf("GetItem RECOVERY: %v", err)
	}
	var rec models.Recovery
	if err := unmarshalItem(recovery.Item, &rec); err != nil {
		t.Fatalf("unmarshal RECOVERY: %v", err)
	}
	if string(rec.LastRewrapToken) != string(in.IdempotencyToken) {
		t.Errorf("RECOVERY LastRewrapToken = %q, want %q", rec.LastRewrapToken, in.IdempotencyToken)
	}
}

// TestRewrapCredentialsNoTokenLeavesFieldUntouched confirms a caller that
// doesn't set IdempotencyToken (changePassword, #30) doesn't clear a token a
// PRIOR re-wrap stored -- RewrapCredentialsInput.IdempotencyToken's own
// comment on why an empty write is avoided rather than relied on to behave
// like "no value."
func TestRewrapCredentialsNoTokenLeavesFieldUntouched(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-rewrap-token-untouched-" + randomSuffix(t)
	reg := testRegisterInput(userID, "rewraptokenuntouched-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	first := testRewrapInput(userID, 1)
	first.IdempotencyToken = []byte("token-a-16-bytes")
	if err := c.RewrapCredentials(ctx, first); err != nil {
		t.Fatalf("first RewrapCredentials: %v", err)
	}

	second := testRewrapInput(userID, 2) // IdempotencyToken left unset, like changePassword
	if err := c.RewrapCredentials(ctx, second); err != nil {
		t.Fatalf("second RewrapCredentials: %v", err)
	}

	recovery, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+userID, "RECOVERY"))
	if err != nil {
		t.Fatalf("GetItem RECOVERY: %v", err)
	}
	var rec models.Recovery
	if err := unmarshalItem(recovery.Item, &rec); err != nil {
		t.Fatalf("unmarshal RECOVERY: %v", err)
	}
	if string(rec.LastRewrapToken) != string(first.IdempotencyToken) {
		t.Errorf("RECOVERY LastRewrapToken = %q, want %q (first re-wrap's, untouched by the second)", rec.LastRewrapToken, first.IdempotencyToken)
	}
	if rec.CredentialVersion != 3 {
		t.Errorf("RECOVERY CredentialVersion = %d, want 3", rec.CredentialVersion)
	}
}

// matchingRewrapMaterial extracts the RewrapMaterial that exactly matches
// what in itself wrote -- what a caller resending the same request would
// present as `want`.
func matchingRewrapMaterial(in RewrapCredentialsInput) RewrapMaterial {
	return RewrapMaterial{
		RecoverySalt:               in.RecoverySalt,
		RecoveryArgon2Params:       in.RecoveryArgon2Params,
		RecoveryWrappedPrivateKeys: in.RecoveryWrappedPrivateKeys,

		RecoveryVerifierSalt:   in.RecoveryVerifierSalt,
		RecoveryVerifierParams: in.RecoveryVerifierParams,
		RecoveryVerifier:       in.RecoveryVerifier,
	}
}

// TestIsOwnRewrapMatches confirms IsOwnRewrap recognizes a token and
// material that both match what's stored, at the exact version a caller's
// own request would have produced.
func TestIsOwnRewrapMatches(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-isownrewrap-match-" + randomSuffix(t)
	reg := testRegisterInput(userID, "isownrewrapmatch-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	in := testRewrapInput(userID, 1)
	in.IdempotencyToken = []byte("token-a-16-bytes")
	if err := c.RewrapCredentials(ctx, in); err != nil {
		t.Fatalf("RewrapCredentials: %v", err)
	}

	isRetry, err := c.IsOwnRewrap(ctx, userID, in.IdempotencyToken, in.NewCredentialVersion, matchingRewrapMaterial(in))
	if err != nil {
		t.Fatalf("IsOwnRewrap: %v", err)
	}
	if !isRetry {
		t.Error("IsOwnRewrap = false, want true (matching token and material at the version this write produced)")
	}
}

// TestIsOwnRewrapWrongTokenFails confirms a different token at the same
// version is not mistaken for a match -- the actual identity check, not
// just the version comparison.
func TestIsOwnRewrapWrongTokenFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-isownrewrap-wrongtoken-" + randomSuffix(t)
	reg := testRegisterInput(userID, "isownrewrapwrongtoken-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	in := testRewrapInput(userID, 1)
	in.IdempotencyToken = []byte("token-a-16-bytes")
	if err := c.RewrapCredentials(ctx, in); err != nil {
		t.Fatalf("RewrapCredentials: %v", err)
	}

	isRetry, err := c.IsOwnRewrap(ctx, userID, []byte("token-b-16-bytes"), in.NewCredentialVersion, matchingRewrapMaterial(in))
	if err != nil {
		t.Fatalf("IsOwnRewrap: %v", err)
	}
	if isRetry {
		t.Error("IsOwnRewrap = true, want false (different token)")
	}
}

// TestIsOwnRewrapWrongVersionFails confirms a matching token at the WRONG
// version is not mistaken for a match -- a stale token from an earlier
// reset must not be replayed against a request it was never for. See
// IsOwnRewrap's own doc comment.
func TestIsOwnRewrapWrongVersionFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-isownrewrap-wrongversion-" + randomSuffix(t)
	reg := testRegisterInput(userID, "isownrewrapwrongversion-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	in := testRewrapInput(userID, 1)
	in.IdempotencyToken = []byte("token-a-16-bytes")
	if err := c.RewrapCredentials(ctx, in); err != nil {
		t.Fatalf("RewrapCredentials: %v", err)
	}

	// Same token, but asking about a version this write did not produce.
	isRetry, err := c.IsOwnRewrap(ctx, userID, in.IdempotencyToken, in.NewCredentialVersion+1, matchingRewrapMaterial(in))
	if err != nil {
		t.Fatalf("IsOwnRewrap: %v", err)
	}
	if isRetry {
		t.Error("IsOwnRewrap = true, want false (right token, wrong version)")
	}
}

// TestIsOwnRewrapEmptyTokenFails confirms an empty token never matches, even
// against a RECOVERY item whose own LastRewrapToken also happens to be empty
// (never set) -- comparing two empty values must not count as a match.
func TestIsOwnRewrapEmptyTokenFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-isownrewrap-emptytoken-" + randomSuffix(t)
	reg := testRegisterInput(userID, "isownrewrapemptytoken-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	in := testRewrapInput(userID, 1) // IdempotencyToken left unset
	if err := c.RewrapCredentials(ctx, in); err != nil {
		t.Fatalf("RewrapCredentials: %v", err)
	}

	isRetry, err := c.IsOwnRewrap(ctx, userID, nil, in.NewCredentialVersion, matchingRewrapMaterial(in))
	if err != nil {
		t.Fatalf("IsOwnRewrap: %v", err)
	}
	if isRetry {
		t.Error("IsOwnRewrap = true, want false (no token presented)")
	}
}

// TestIsOwnRewrapWrongMaterialFails is the material-comparison analogue of
// TestRegisterRetryWithDifferentKeyMaterialStillFails (PR #133 round 1's
// finding, applied to IsOwnRewrap): a token and version that both match, but
// material that doesn't, must not be treated as a retry -- otherwise a
// caller resending the same token with different fields would get back a
// false "success" for a write that never actually happened with those
// fields.
func TestIsOwnRewrapWrongMaterialFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-isownrewrap-wrongmaterial-" + randomSuffix(t)
	reg := testRegisterInput(userID, "isownrewrapwrongmaterial-"+randomSuffix(t))
	if err := c.Register(ctx, reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	in := testRewrapInput(userID, 1)
	in.IdempotencyToken = []byte("token-a-16-bytes")
	if err := c.RewrapCredentials(ctx, in); err != nil {
		t.Fatalf("RewrapCredentials: %v", err)
	}

	// Same token, same version -- but a different recovery verifier than
	// what was actually stored.
	want := matchingRewrapMaterial(in)
	want.RecoveryVerifier = []byte("different-verifier-entirely")
	isRetry, err := c.IsOwnRewrap(ctx, userID, in.IdempotencyToken, in.NewCredentialVersion, want)
	if err != nil {
		t.Fatalf("IsOwnRewrap: %v", err)
	}
	if isRetry {
		t.Error("IsOwnRewrap = true, want false (token and version match, but material does not)")
	}
}
