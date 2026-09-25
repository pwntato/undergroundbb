package db

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/pwntato/undergroundbb/internal/models"
)

// testClient builds a Client against DYNAMODB_ENDPOINT (DynamoDB Local, set
// by docker-compose.yml / .github/workflows/test.yml), skipping the test
// when it isn't set rather than failing -- so `go test ./...` still passes
// for anyone who hasn't started the local DynamoDB container. TABLE_NAME
// defaults to "undergroundbb" to match local-setup.sh and CI.
func testClient(t *testing.T) *Client {
	t.Helper()
	endpoint := os.Getenv("DYNAMODB_ENDPOINT")
	if endpoint == "" {
		t.Skip("DYNAMODB_ENDPOINT not set; run `docker compose up -d && ./scripts/local-setup.sh` to test against DynamoDB Local")
	}
	table := os.Getenv("TABLE_NAME")
	if table == "" {
		table = "undergroundbb"
	}
	c, err := New(context.Background(), table, endpoint)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func testRegisterInput(userID, username string) RegisterInput {
	return RegisterInput{
		UserID:            userID,
		Username:          username,
		UsernameLower:     username, // callers pass already-lowercased usernames in these tests
		SigningPublicKey:  make([]byte, 32),
		WrappingPublicKey: make([]byte, 32),

		Salt:         []byte("salt"),
		Argon2Params: models.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1},
		WrappedPrivateKeys: models.WrappedBlob{
			Nonce:      make([]byte, 12),
			Ciphertext: []byte("ciphertext"),
		},

		RecoverySalt:         []byte("recovery-salt"),
		RecoveryArgon2Params: models.Argon2Params{MemoryKiB: 65536, Iterations: 3, Parallelism: 1},
		RecoveryWrappedPrivateKeys: models.WrappedBlob{
			Nonce:      make([]byte, 12),
			Ciphertext: []byte("recovery-ciphertext"),
		},

		RecoveryVerifierSalt:   []byte("recovery-verifier-salt"),
		RecoveryVerifierParams: models.Argon2Params{MemoryKiB: 19456, Iterations: 2, Parallelism: 1},
		RecoveryVerifier:       []byte("recovery-verifier"),
	}
}

func TestRegisterWritesAllThreeItems(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	in := testRegisterInput("test-register-alice-"+randomSuffix(t), "alice-"+randomSuffix(t))
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	user, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+in.UserID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	if user.Item == nil {
		t.Error("PROFILE item was not written")
	}

	recovery, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+in.UserID, "RECOVERY"))
	if err != nil {
		t.Fatalf("GetItem RECOVERY: %v", err)
	}
	if recovery.Item == nil {
		t.Fatal("RECOVERY item was not written")
	}
	var recoveryItem models.Recovery
	if err := unmarshalItem(recovery.Item, &recoveryItem); err != nil {
		t.Fatalf("unmarshal RECOVERY: %v", err)
	}
	// The verifier fields are what #31's recovery-release/reset endpoints
	// gate on -- distinct from Salt/Argon2Params/WrappedPrivateKeys above,
	// see models.Recovery's own doc comment on why they're a separate
	// derivation.
	if string(recoveryItem.VerifierSalt) != string(in.RecoveryVerifierSalt) {
		t.Errorf("RECOVERY VerifierSalt = %q, want %q", recoveryItem.VerifierSalt, in.RecoveryVerifierSalt)
	}
	if recoveryItem.VerifierArgon2Params != in.RecoveryVerifierParams {
		t.Errorf("RECOVERY VerifierArgon2Params = %+v, want %+v", recoveryItem.VerifierArgon2Params, in.RecoveryVerifierParams)
	}
	if string(recoveryItem.Verifier) != string(in.RecoveryVerifier) {
		t.Errorf("RECOVERY Verifier = %q, want %q", recoveryItem.Verifier, in.RecoveryVerifier)
	}

	claim, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USERNAME#"+in.UsernameLower, "CLAIM"))
	if err != nil {
		t.Fatalf("GetItem CLAIM: %v", err)
	}
	if claim.Item == nil {
		t.Error("CLAIM item was not written")
	}
}

// TestRegisterUsernameTaken covers the sequential case: a second signup for
// a username that already has a claim is rejected, and rejected with
// ErrUsernameTaken specifically rather than a generic error, so a handler
// can return 409 instead of 500.
func TestRegisterUsernameTaken(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "bob-" + randomSuffix(t)
	first := testRegisterInput("test-register-bob-1-"+randomSuffix(t), username)
	if err := c.Register(ctx, first); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	second := testRegisterInput("test-register-bob-2-"+randomSuffix(t), username)
	err := c.Register(ctx, second)
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("second Register error = %v, want ErrUsernameTaken", err)
	}

	// The loser's PROFILE must not exist -- Register must not have written
	// the user/recovery items outside the transaction before the claim
	// failed, which would reproduce exactly the "profile written, claim
	// not" partial-write case docs/DESIGN.md names as unreachable-by-design.
	user, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+second.UserID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	if user.Item != nil {
		t.Error("losing Register call's PROFILE item was written despite the claim failing")
	}
}

// TestRegisterUserIDTaken covers ErrUserIDTaken directly at the db layer:
// two Register calls with different usernames but the same UserID must have
// the second rejected, and must not clobber the first registration's
// PROFILE item. UserID is now caller-supplied rather than always a fresh
// idgen.UUID() (see RegisterInput's own doc comment), so unlike
// TestRegisterUsernameTaken above -- which exercises a condition that
// existed before this change -- this is the new collision surface a
// client-chosen id introduces.
func TestRegisterUserIDTaken(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	sharedID := "test-register-dave-shared-" + randomSuffix(t)
	first := testRegisterInput(sharedID, "dave-"+randomSuffix(t))
	if err := c.Register(ctx, first); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	second := testRegisterInput(sharedID, "dave-second-"+randomSuffix(t))
	err := c.Register(ctx, second)
	if !errors.Is(err, ErrUserIDTaken) {
		t.Fatalf("second Register error = %v, want ErrUserIDTaken", err)
	}

	// The first registration's PROFILE must be exactly what it wrote --
	// the rejected second attempt sharing the same PK must not have landed
	// any of its own item there, transactionally or otherwise.
	user, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+sharedID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	if user.Item == nil {
		t.Fatal("first registration's PROFILE item is missing")
	}
	var userItem models.User
	if err := unmarshalItem(user.Item, &userItem); err != nil {
		t.Fatalf("unmarshal PROFILE: %v", err)
	}
	if userItem.Username != first.Username {
		t.Errorf("PROFILE Username = %q, want %q (first registration's, unclobbered)", userItem.Username, first.Username)
	}

	// The second (losing) username must remain unclaimed.
	secondClaim, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USERNAME#"+second.UsernameLower, "CLAIM"))
	if err != nil {
		t.Fatalf("GetItem CLAIM: %v", err)
	}
	if secondClaim.Item != nil {
		t.Error("losing Register call's username claim was written despite the userId conflict")
	}
}

// TestRegisterUsernameTakenConcurrent is the race this project's CI
// explicitly calls out signup for (.github/workflows/test.yml: "the design
// has five contested writes ... whose tests exercise concurrency"). Two
// concurrent Register calls for the same username race for one claim; the
// condition on attribute_not_exists(PK) must let exactly one win, not zero
// and not both -- see docs/DESIGN.md, "The claim is only a claim because
// the write is conditional."
func TestRegisterUsernameTakenConcurrent(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "carol-" + randomSuffix(t)
	a := testRegisterInput("test-register-carol-a-"+randomSuffix(t), username)
	b := testRegisterInput("test-register-carol-b-"+randomSuffix(t), username)

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = c.Register(ctx, a) }()
	go func() { defer wg.Done(); errs[1] = c.Register(ctx, b) }()
	wg.Wait()

	wins, losses := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrUsernameTaken):
			losses++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("wins=%d losses=%d, want exactly one winner and one loser", wins, losses)
	}

	// The claim must resolve to whichever UserID actually won, not just
	// "a claim exists" -- otherwise a claim pointing at the loser's
	// never-written PROFILE would reproduce the unreachable-account bug the
	// transaction exists to prevent.
	winnerID := a.UserID
	if errs[0] != nil {
		winnerID = b.UserID
	}
	claim, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USERNAME#"+username, "CLAIM"))
	if err != nil {
		t.Fatalf("GetItem CLAIM: %v", err)
	}
	if claim.Item == nil {
		t.Fatal("CLAIM item missing after concurrent registration")
	}
	var got models.UsernameClaim
	if err := unmarshalItem(claim.Item, &got); err != nil {
		t.Fatalf("unmarshal claim: %v", err)
	}
	if got.UserID != winnerID {
		t.Errorf("claim.UserID = %q, want winner %q", got.UserID, winnerID)
	}
}

// TestRegisterUserIDTakenConcurrent is TestRegisterUsernameTakenConcurrent's
// counterpart for the PROFILE write's own condition, now load-bearing
// because UserID is caller-supplied (see RegisterInput's own doc comment).
// Two concurrent Register calls sharing one UserID but distinct usernames
// race for one PROFILE write; exactly one must win.
func TestRegisterUserIDTakenConcurrent(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	sharedID := "test-register-erin-shared-" + randomSuffix(t)
	a := testRegisterInput(sharedID, "erin-a-"+randomSuffix(t))
	b := testRegisterInput(sharedID, "erin-b-"+randomSuffix(t))

	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = c.Register(ctx, a) }()
	go func() { defer wg.Done(); errs[1] = c.Register(ctx, b) }()
	wg.Wait()

	wins, losses := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrUserIDTaken):
			losses++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins != 1 || losses != 1 {
		t.Fatalf("wins=%d losses=%d, want exactly one winner and one loser", wins, losses)
	}

	// The PROFILE item must reflect whichever registration actually won,
	// not a mix -- e.g. the winner's Username with the loser's other
	// fields, which an unconditional overwrite outside this transaction
	// could otherwise produce.
	winner := a
	if errs[0] != nil {
		winner = b
	}
	user, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+sharedID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	if user.Item == nil {
		t.Fatal("PROFILE item missing after concurrent registration")
	}
	var got models.User
	if err := unmarshalItem(user.Item, &got); err != nil {
		t.Fatalf("unmarshal PROFILE: %v", err)
	}
	if got.Username != winner.Username {
		t.Errorf("PROFILE Username = %q, want winner's %q", got.Username, winner.Username)
	}
}

// TestRegisterRetryAfterLostResponseSucceeds is issue #124: a client that
// registered successfully but never saw the response (timeout, cold Lambda
// path, flaky mobile connection) naturally retries with the identical
// registerRequest -- same UserID, same username. Both the PROFILE and CLAIM
// conditions fail on that retry, exactly as they would for a genuine
// conflict, but this must resolve as success rather than ErrUsernameTaken:
// the caller is being told someone else took a username they themselves
// just registered.
func TestRegisterRetryAfterLostResponseSucceeds(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	in := testRegisterInput("test-register-retry-"+randomSuffix(t), "retry-"+randomSuffix(t))
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	// The identical request, resent -- not a copy with a new UserID, the
	// exact same RegisterInput a real client-side retry would resend.
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("retry Register: %v, want nil (idempotent success)", err)
	}

	// The original PROFILE must be untouched -- a retry succeeding must not
	// have re-run the transaction and silently overwritten anything.
	user, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+in.UserID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	if user.Item == nil {
		t.Fatal("PROFILE item missing after retry")
	}
	var got models.User
	if err := unmarshalItem(user.Item, &got); err != nil {
		t.Fatalf("unmarshal PROFILE: %v", err)
	}
	if got.Username != in.Username {
		t.Errorf("PROFILE Username = %q, want %q (unchanged by retry)", got.Username, in.Username)
	}
}

// TestRegisterMismatchedRetryStillFails covers the other shape that can
// produce a double conditional failure: a request whose PROFILE already
// exists under its UserID (from some earlier registration) but whose
// username belongs to a *different* account's claim. This is not the
// caller's own earlier write -- issue #124's fix must not treat every
// double failure as a retry, only ones where the claim actually points back
// at the same UserID making the request.
func TestRegisterMismatchedRetryStillFails(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Two real, distinct accounts already registered.
	first := testRegisterInput("test-register-mismatch-a-"+randomSuffix(t), "mismatch-a-"+randomSuffix(t))
	if err := c.Register(ctx, first); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	second := testRegisterInput("test-register-mismatch-b-"+randomSuffix(t), "mismatch-b-"+randomSuffix(t))
	if err := c.Register(ctx, second); err != nil {
		t.Fatalf("second Register: %v", err)
	}

	// A third attempt claims to be `first`'s UserID (so the PROFILE
	// condition fails) but under `second`'s already-claimed username (so
	// the CLAIM condition fails too) -- a double failure, but the claim it
	// collides with does not point at this UserID, so it must not be
	// mistaken for first's own retry.
	mismatched := testRegisterInput(first.UserID, second.Username)
	err := c.Register(ctx, mismatched)
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("mismatched Register error = %v, want ErrUsernameTaken", err)
	}

	// Neither original account's PROFILE may have been disturbed.
	firstUser, err := c.ddb.GetItem(ctx, getItemInput(c.table, "USER#"+first.UserID, "PROFILE"))
	if err != nil {
		t.Fatalf("GetItem PROFILE: %v", err)
	}
	var gotFirst models.User
	if err := unmarshalItem(firstUser.Item, &gotFirst); err != nil {
		t.Fatalf("unmarshal PROFILE: %v", err)
	}
	if gotFirst.Username != first.Username {
		t.Errorf("first's PROFILE Username = %q, want %q (unchanged)", gotFirst.Username, first.Username)
	}
}
