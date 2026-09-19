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

// TestRecordFailedVerifyResetsAfterLockExpiry is the fix for PR #117 round-1
// review's blocking finding: the lockout counter previously only ever
// incremented, so a single failure after an expired lock re-locked the
// account for a full lockDuration, indefinitely -- reproduced live by the
// reviewer against DynamoDB Local. This pins that a failure observed AFTER
// an expired lock resets to a fresh budget (count = 1, no re-lock) rather
// than treating the stale FailedVerifyCount as still current.
func TestRecordFailedVerifyResetsAfterLockExpiry(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "resetexpiry-" + randomSuffix(t)
	in := testRegisterInput("test-resetexpiry-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const threshold = 3
	// LockUntil is stored as RFC3339 (second resolution, no fractional
	// seconds -- see models.User.LockUntil), so the lockDuration here has to
	// be negative by at least a couple of whole seconds to reliably compare
	// as "before now" in the SET .. REMOVE LockUntil condition -- a
	// millisecond-scale duration can round into the same second as the
	// comparison and the condition would never observably differ from "not
	// yet expired." Setting it a few seconds in the PAST directly is both
	// simpler and avoids any real sleep in this test.
	const alreadyExpiredLockDuration = -3 * time.Second

	for range threshold {
		if err := c.RecordFailedVerify(ctx, in.UserID, threshold, alreadyExpiredLockDuration); err != nil {
			t.Fatalf("RecordFailedVerify: %v", err)
		}
	}
	user, err := c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.LockUntil == "" {
		t.Fatal("test setup: expected to be locked after reaching the threshold")
	}
	firstLockUntil := user.LockUntil

	// One failure against an already-past LockUntil must reset to a fresh
	// budget, not re-lock immediately -- this is exactly the bug: the old
	// implementation set FailedVerifyCount to threshold+1 here (still >=
	// threshold) and re-locked for another full lockDuration.
	if err := c.RecordFailedVerify(ctx, in.UserID, threshold, alreadyExpiredLockDuration); err != nil {
		t.Fatalf("RecordFailedVerify (post-expiry): %v", err)
	}
	user, err = c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.FailedVerifyCount != 1 {
		t.Errorf("FailedVerifyCount after one post-expiry failure = %d, want 1 (fresh budget)", user.FailedVerifyCount)
	}
	if user.LockUntil != "" {
		t.Errorf("LockUntil = %q after a single post-expiry failure (threshold %d), want empty -- re-locked on one attempt", user.LockUntil, threshold)
	}
	if user.LockUntil == firstLockUntil {
		t.Error("LockUntil unchanged -- reset did not actually run")
	}

	// Confirm the fresh budget really does take threshold-many failures to
	// re-lock, not just one. The reset above already left the count at 1, so
	// threshold-2 more calls stay strictly below threshold (1 + (threshold-2)
	// = threshold-1), and one further call after that reaches it exactly.
	for i := 0; i < threshold-2; i++ {
		if err := c.RecordFailedVerify(ctx, in.UserID, threshold, time.Minute); err != nil {
			t.Fatalf("RecordFailedVerify (rebuild %d): %v", i, err)
		}
	}
	user, err = c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.FailedVerifyCount != threshold-1 {
		t.Fatalf("FailedVerifyCount = %d, want %d (one below threshold)", user.FailedVerifyCount, threshold-1)
	}
	if user.LockUntil != "" {
		t.Fatalf("LockUntil = %q before reaching the fresh threshold again, want empty", user.LockUntil)
	}
	if err := c.RecordFailedVerify(ctx, in.UserID, threshold, time.Minute); err != nil {
		t.Fatalf("RecordFailedVerify (rebuild threshold): %v", err)
	}
	user, err = c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.LockUntil == "" {
		t.Error("LockUntil is empty after rebuilding to the threshold again, want locked")
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
