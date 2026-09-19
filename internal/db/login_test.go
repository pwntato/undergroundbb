package db

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLookupUserByUsername(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "login-lookup-" + randomSuffix(t)
	in := testRegisterInput("test-login-lookup-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	user, err := c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.Username != username {
		t.Errorf("Username = %q, want %q", user.Username, username)
	}
	if user.PK != "USER#"+in.UserID {
		t.Errorf("PK = %q, want %q", user.PK, "USER#"+in.UserID)
	}
}

func TestLookupUserByUsernameNotFound(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, err := c.LookupUserByUsername(ctx, "no-such-user-"+randomSuffix(t))
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

func TestPutAndConsumeChallenge(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-challenge-" + randomSuffix(t)
	nonce := []byte("a-test-nonce-value-32-bytes-longX")

	if err := c.PutChallenge(ctx, userID, nonce, 2*time.Minute); err != nil {
		t.Fatalf("PutChallenge: %v", err)
	}

	if err := c.ConsumeChallenge(ctx, userID, nonce); err != nil {
		t.Fatalf("ConsumeChallenge: %v", err)
	}

	// Second consume of the same nonce must fail -- single-use.
	if err := c.ConsumeChallenge(ctx, userID, nonce); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("second ConsumeChallenge err = %v, want ErrChallengeMismatch", err)
	}
}

func TestConsumeChallengeWrongNonce(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-challenge-wrong-" + randomSuffix(t)
	nonce := []byte("the-real-nonce-that-was-issued-01")
	wrongNonce := []byte("a-completely-different-nonce-here")

	if err := c.PutChallenge(ctx, userID, nonce, 2*time.Minute); err != nil {
		t.Fatalf("PutChallenge: %v", err)
	}

	if err := c.ConsumeChallenge(ctx, userID, wrongNonce); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("err = %v, want ErrChallengeMismatch", err)
	}

	// The real challenge must still be there and consumable -- a wrong-nonce
	// attempt must not have deleted it.
	if err := c.ConsumeChallenge(ctx, userID, nonce); err != nil {
		t.Errorf("ConsumeChallenge with correct nonce after a wrong attempt: %v", err)
	}
}

// TestConsumeChallengeStaleAfterOverwrite is the scenario ConsumeChallenge's
// own doc comment names as the reason to condition on the nonce VALUE, not
// merely the item's existence: PutChallenge is single-slot, so a second call
// overwrites the first. A client still holding the FIRST nonce must not be
// able to consume the SECOND (unrelated) challenge that replaced it.
func TestConsumeChallengeStaleAfterOverwrite(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-challenge-overwrite-" + randomSuffix(t)
	firstNonce := []byte("first-issued-nonce-now-stale-0001")
	secondNonce := []byte("second-issued-nonce-now-current01")

	if err := c.PutChallenge(ctx, userID, firstNonce, 2*time.Minute); err != nil {
		t.Fatalf("PutChallenge (first): %v", err)
	}
	if err := c.PutChallenge(ctx, userID, secondNonce, 2*time.Minute); err != nil {
		t.Fatalf("PutChallenge (second): %v", err)
	}

	// The stale first nonce must not consume the second challenge.
	if err := c.ConsumeChallenge(ctx, userID, firstNonce); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("stale nonce consume err = %v, want ErrChallengeMismatch", err)
	}

	// The current second nonce must still work.
	if err := c.ConsumeChallenge(ctx, userID, secondNonce); err != nil {
		t.Errorf("ConsumeChallenge with current nonce: %v", err)
	}
}

func TestConsumeChallengeNoChallenge(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	err := c.ConsumeChallenge(ctx, "test-no-challenge-"+randomSuffix(t), []byte("any-nonce-value-here-doesnt-matter"))
	if !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("err = %v, want ErrChallengeMismatch", err)
	}
}

func TestRecordFailedVerifyIncrementsAndLocks(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "failverify-" + randomSuffix(t)
	in := testRegisterInput("test-failverify-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const threshold = 3
	for i := 1; i < threshold; i++ {
		if err := c.RecordFailedVerify(ctx, in.UserID, threshold, time.Minute); err != nil {
			t.Fatalf("RecordFailedVerify (attempt %d): %v", i, err)
		}
		user, err := c.LookupUserByUsername(ctx, username)
		if err != nil {
			t.Fatalf("LookupUserByUsername: %v", err)
		}
		if user.LockUntil != "" {
			t.Fatalf("attempt %d: LockUntil = %q, want empty (below threshold)", i, user.LockUntil)
		}
	}

	// The threshold-th failure must lock.
	if err := c.RecordFailedVerify(ctx, in.UserID, threshold, time.Minute); err != nil {
		t.Fatalf("RecordFailedVerify (threshold): %v", err)
	}
	user, err := c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.LockUntil == "" {
		t.Fatal("LockUntil is empty after reaching the threshold, want a timestamp")
	}
	lockedUntil, err := time.Parse(time.RFC3339, user.LockUntil)
	if err != nil {
		t.Fatalf("LockUntil is not RFC3339: %v", err)
	}
	if !lockedUntil.After(time.Now()) {
		t.Errorf("LockUntil = %s, want a time in the future", lockedUntil)
	}
}

func TestClearFailedVerify(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "clearverify-" + randomSuffix(t)
	in := testRegisterInput("test-clearverify-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for range 5 {
		if err := c.RecordFailedVerify(ctx, in.UserID, 5, time.Minute); err != nil {
			t.Fatalf("RecordFailedVerify: %v", err)
		}
	}
	user, err := c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.LockUntil == "" {
		t.Fatal("test setup: expected to be locked before ClearFailedVerify")
	}

	if err := c.ClearFailedVerify(ctx, in.UserID); err != nil {
		t.Fatalf("ClearFailedVerify: %v", err)
	}
	user, err = c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.FailedVerifyCount != 0 {
		t.Errorf("FailedVerifyCount = %d, want 0", user.FailedVerifyCount)
	}
	if user.LockUntil != "" {
		t.Errorf("LockUntil = %q, want empty", user.LockUntil)
	}
}
