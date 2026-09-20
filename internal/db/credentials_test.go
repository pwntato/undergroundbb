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
