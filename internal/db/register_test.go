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

	in := testRegisterInput("test-register-alice", "alice-"+randomSuffix(t))
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
	first := testRegisterInput("test-register-bob-1", username)
	if err := c.Register(ctx, first); err != nil {
		t.Fatalf("first Register: %v", err)
	}

	second := testRegisterInput("test-register-bob-2", username)
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
	a := testRegisterInput("test-register-carol-a", username)
	b := testRegisterInput("test-register-carol-b", username)

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
