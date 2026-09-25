package db

import (
	"context"
	"testing"
	"time"
)

func TestGetRecoveryNotFound(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	_, err := c.GetRecovery(ctx, "no-such-user-"+randomSuffix(t))
	if err != ErrUserNotFound {
		t.Errorf("err = %v, want ErrUserNotFound", err)
	}
}

// TestRecordFailedRecoveryVerifyIncrementsAndLocks and the tests below mirror
// login_test.go's RecordFailedVerify coverage exactly, but against
// RECOVERY's own FailedVerifyCount/LockUntil (issue #136) -- see
// resolveRecovery's doc comment (internal/handlers/recovery.go) for why this
// is a distinct counter from User's.
func TestRecordFailedRecoveryVerifyIncrementsAndLocks(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "recfailverify-" + randomSuffix(t)
	in := testRegisterInput("test-recfailverify-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const threshold = 3
	for i := 1; i < threshold; i++ {
		if err := c.RecordFailedRecoveryVerify(ctx, in.UserID, threshold, time.Minute); err != nil {
			t.Fatalf("RecordFailedRecoveryVerify (attempt %d): %v", i, err)
		}
		rec, err := c.GetRecovery(ctx, in.UserID)
		if err != nil {
			t.Fatalf("GetRecovery: %v", err)
		}
		if rec.LockUntil != "" {
			t.Fatalf("attempt %d: LockUntil = %q, want empty (below threshold)", i, rec.LockUntil)
		}
	}

	// The threshold-th failure must lock.
	if err := c.RecordFailedRecoveryVerify(ctx, in.UserID, threshold, time.Minute); err != nil {
		t.Fatalf("RecordFailedRecoveryVerify (threshold): %v", err)
	}
	rec, err := c.GetRecovery(ctx, in.UserID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.LockUntil == "" {
		t.Fatal("LockUntil is empty after reaching the threshold, want a timestamp")
	}
	lockedUntil, err := time.Parse(time.RFC3339, rec.LockUntil)
	if err != nil {
		t.Fatalf("LockUntil is not RFC3339: %v", err)
	}
	if !lockedUntil.After(time.Now()) {
		t.Errorf("LockUntil = %s, want a time in the future", lockedUntil)
	}
}

// TestRecordFailedRecoveryVerifyResetsAfterLockExpiry pins the same rolling-
// window behavior login.go's RecordFailedVerify has (and the same bug class
// PR #117 round-1 review found there): a failure observed after an already-
// expired lock must reset to a fresh budget, not re-lock immediately.
func TestRecordFailedRecoveryVerifyResetsAfterLockExpiry(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "recresetexpiry-" + randomSuffix(t)
	in := testRegisterInput("test-recresetexpiry-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	const threshold = 3
	// See login_test.go's TestRecordFailedVerifyResetsAfterLockExpiry for why
	// this needs to be a few whole seconds in the past rather than a small
	// negative duration -- LockUntil is RFC3339 at second resolution.
	const alreadyExpiredLockDuration = -3 * time.Second

	for range threshold {
		if err := c.RecordFailedRecoveryVerify(ctx, in.UserID, threshold, alreadyExpiredLockDuration); err != nil {
			t.Fatalf("RecordFailedRecoveryVerify: %v", err)
		}
	}
	rec, err := c.GetRecovery(ctx, in.UserID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.LockUntil == "" {
		t.Fatal("test setup: expected to be locked after reaching the threshold")
	}
	firstLockUntil := rec.LockUntil

	if err := c.RecordFailedRecoveryVerify(ctx, in.UserID, threshold, alreadyExpiredLockDuration); err != nil {
		t.Fatalf("RecordFailedRecoveryVerify (post-expiry): %v", err)
	}
	rec, err = c.GetRecovery(ctx, in.UserID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.FailedVerifyCount != 1 {
		t.Errorf("FailedVerifyCount after one post-expiry failure = %d, want 1 (fresh budget)", rec.FailedVerifyCount)
	}
	if rec.LockUntil != "" {
		t.Errorf("LockUntil = %q after a single post-expiry failure (threshold %d), want empty -- re-locked on one attempt", rec.LockUntil, threshold)
	}
	if rec.LockUntil == firstLockUntil {
		t.Error("LockUntil unchanged -- reset did not actually run")
	}
}

func TestClearFailedRecoveryVerify(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "recclearverify-" + randomSuffix(t)
	in := testRegisterInput("test-recclearverify-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for range 5 {
		if err := c.RecordFailedRecoveryVerify(ctx, in.UserID, 5, time.Minute); err != nil {
			t.Fatalf("RecordFailedRecoveryVerify: %v", err)
		}
	}
	rec, err := c.GetRecovery(ctx, in.UserID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.LockUntil == "" {
		t.Fatal("test setup: expected to be locked before ClearFailedRecoveryVerify")
	}

	if err := c.ClearFailedRecoveryVerify(ctx, in.UserID); err != nil {
		t.Fatalf("ClearFailedRecoveryVerify: %v", err)
	}
	rec, err = c.GetRecovery(ctx, in.UserID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.FailedVerifyCount != 0 {
		t.Errorf("FailedVerifyCount = %d, want 0", rec.FailedVerifyCount)
	}
	if rec.LockUntil != "" {
		t.Errorf("LockUntil = %q, want empty", rec.LockUntil)
	}
}

// TestRecordFailedRecoveryVerifyDoesNotTouchUserLockout confirms RECOVERY's
// lockout pair is genuinely independent of PROFILE's -- the entire reason
// #136 added a separate counter instead of reusing User.FailedVerifyCount.
func TestRecordFailedRecoveryVerifyDoesNotTouchUserLockout(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	username := "recnotuser-" + randomSuffix(t)
	in := testRegisterInput("test-recnotuser-"+randomSuffix(t), username)
	if err := c.Register(ctx, in); err != nil {
		t.Fatalf("Register: %v", err)
	}

	for range 5 {
		if err := c.RecordFailedRecoveryVerify(ctx, in.UserID, 5, time.Minute); err != nil {
			t.Fatalf("RecordFailedRecoveryVerify: %v", err)
		}
	}
	rec, err := c.GetRecovery(ctx, in.UserID)
	if err != nil {
		t.Fatalf("GetRecovery: %v", err)
	}
	if rec.LockUntil == "" {
		t.Fatal("test setup: expected RECOVERY to be locked")
	}

	user, err := c.LookupUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("LookupUserByUsername: %v", err)
	}
	if user.FailedVerifyCount != 0 {
		t.Errorf("User.FailedVerifyCount = %d, want 0 -- recovery failures must not touch the login counter", user.FailedVerifyCount)
	}
	if user.LockUntil != "" {
		t.Errorf("User.LockUntil = %q, want empty -- recovery failures must never lock login", user.LockUntil)
	}
}
