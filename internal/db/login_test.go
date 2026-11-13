package db

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/pwntato/undergroundbb/internal/models"
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

// The production numbers (handlers' challengeTTL and challengeMinUsable), repeated here because
// this package cannot import handlers. A test that changes them is testing something else.
const (
	testChallengeTTL       = 2 * time.Minute
	testChallengeMinUsable = 45 * time.Second
)

// seedChallenge issues nonce for userID now and fails the test unless exactly that nonce comes
// back, which it does for any user with no live challenge.
func seedChallenge(t *testing.T, c *Client, userID string, nonce []byte) {
	t.Helper()
	got, err := c.IssueChallenge(context.Background(), userID, nonce, testChallengeTTL, testChallengeMinUsable, time.Now())
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if !bytes.Equal(got, nonce) {
		t.Fatalf("IssueChallenge returned a different nonce for a user with no challenge")
	}
}

// challengeRows reads every CHALLENGE* row of userID straight from the table, so a test can check
// how many exist (the cardinality bound) and what each holds.
func challengeRows(t *testing.T, c *Client, userID string) []challengeSlot {
	t.Helper()
	slots, err := c.readChallengeSlots(context.Background(), userID)
	if err != nil {
		t.Fatalf("readChallengeSlots: %v", err)
	}
	return slots
}

func randNonce(t *testing.T) []byte {
	t.Helper()
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return n
}

func TestIssueAndConsumeChallenge(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-challenge-" + randomSuffix(t)
	nonce := []byte("a-test-nonce-value-32-bytes-longX")
	seedChallenge(t, c, userID, nonce)

	if err := c.ConsumeChallenge(ctx, userID, nonce, time.Now()); err != nil {
		t.Fatalf("ConsumeChallenge: %v", err)
	}

	// Second consume of the same nonce must fail -- single-use.
	if err := c.ConsumeChallenge(ctx, userID, nonce, time.Now()); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("second ConsumeChallenge err = %v, want ErrChallengeMismatch", err)
	}
}

func TestConsumeChallengeWrongNonce(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	userID := "test-challenge-wrong-" + randomSuffix(t)
	nonce := []byte("the-real-nonce-that-was-issued-01")
	wrongNonce := []byte("a-completely-different-nonce-here")
	seedChallenge(t, c, userID, nonce)

	if err := c.ConsumeChallenge(ctx, userID, wrongNonce, time.Now()); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("err = %v, want ErrChallengeMismatch", err)
	}

	// The real challenge must still be there and consumable -- a wrong-nonce
	// attempt must not have deleted it.
	if err := c.ConsumeChallenge(ctx, userID, nonce, time.Now()); err != nil {
		t.Errorf("ConsumeChallenge with correct nonce after a wrong attempt: %v", err)
	}
}

// A second request inside the window is handed the nonce already waiting, not a new one (#390).
// This is what stops a flood from replacing the nonce a real user is still deriving a signature
// for, and it must not add an item.
func TestIssueChallengeReturnsTheWaitingNonce(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-issue-same-" + randomSuffix(t)
	now := time.Now()

	first := randNonce(t)
	got, err := c.IssueChallenge(ctx, userID, first, testChallengeTTL, testChallengeMinUsable, now)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("first issue = %x, %v; want %x", got, err, first)
	}
	for i := range 20 {
		got, err := c.IssueChallenge(ctx, userID, randNonce(t), testChallengeTTL, testChallengeMinUsable, now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatalf("issue %d: %v", i, err)
		}
		if !bytes.Equal(got, first) {
			t.Fatalf("issue %d returned a new nonce while the first had %ds left", i, 120-i)
		}
	}
	if rows := challengeRows(t, c, userID); len(rows) != 1 {
		t.Errorf("%d challenge rows after repeated requests, want 1", len(rows))
	}
}

// The nonce being retired must stay spendable until it has really expired. This is the property a
// single slot with a "refresh when under a minute is left" rule cannot give: that refresh
// overwrites a nonce handed out moments earlier.
func TestIssueChallengeRetiringNonceStaysSpendable(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-issue-retire-" + randomSuffix(t)
	now := time.Now()

	first := randNonce(t)
	if _, err := c.IssueChallenge(ctx, userID, first, testChallengeTTL, testChallengeMinUsable, now); err != nil {
		t.Fatalf("issue first: %v", err)
	}
	// 80s later the first has 40s left, under the 45s floor, so a new nonce goes in the other slot.
	second := randNonce(t)
	got, err := c.IssueChallenge(ctx, userID, second, testChallengeTTL, testChallengeMinUsable, now.Add(80*time.Second))
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("issue at 80s = %x, %v; want the new nonce %x", got, err, second)
	}
	if rows := challengeRows(t, c, userID); len(rows) != 2 {
		t.Fatalf("%d rows, want both slots in use", len(rows))
	}
	// A user handed `first` at 79s is still inside its life and must be able to spend it.
	spendAt := now.Add(85 * time.Second)
	if err := c.ConsumeChallenge(ctx, userID, first, spendAt); err != nil {
		t.Errorf("retiring nonce could not be spent: %v", err)
	}
	if err := c.ConsumeChallenge(ctx, userID, second, spendAt); err != nil {
		t.Errorf("new nonce could not be spent: %v", err)
	}
}

// An expired nonce is replaced, and an expired row that DynamoDB has not swept yet counts as
// absent: expiry is judged against the clock, never by whether the row exists.
func TestIssueChallengeReplacesExpired(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-issue-expired-" + randomSuffix(t)
	now := time.Now()

	old := randNonce(t)
	if _, err := c.IssueChallenge(ctx, userID, old, testChallengeTTL, testChallengeMinUsable, now); err != nil {
		t.Fatalf("issue old: %v", err)
	}
	fresh := randNonce(t)
	got, err := c.IssueChallenge(ctx, userID, fresh, testChallengeTTL, testChallengeMinUsable, now.Add(testChallengeTTL+time.Second))
	if err != nil || !bytes.Equal(got, fresh) {
		t.Fatalf("issue after expiry = %x, %v; want %x", got, err, fresh)
	}
	// The expired nonce no longer matches anything: its slot was rewritten.
	if err := c.ConsumeChallenge(ctx, userID, old, now.Add(testChallengeTTL+2*time.Second)); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("expired nonce consume err = %v, want ErrChallengeMismatch", err)
	}
}

// The scenario of #390 itself, across simulated minutes: somebody requests a challenge for the
// user every second, and the user logs in over and over, taking 40s to derive and sign each time
// (a slow phone). Every login must land, and the partition must never hold more than two rows.
func TestIssueChallengeSurvivesAFlood(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-issue-flood-" + randomSuffix(t)
	start := time.Now()
	const derive = 40 * time.Second // under testChallengeMinUsable

	var userNonce []byte
	var consumeAt time.Duration
	logins := 0
	for sec := 0; sec <= 600; sec++ {
		at := time.Duration(sec) * time.Second
		now := start.Add(at)

		// The user's browser finishes deriving and sends its signature.
		if userNonce != nil && at >= consumeAt {
			if err := c.ConsumeChallenge(ctx, userID, userNonce, now); err != nil {
				t.Fatalf("login %d: the user's nonce, handed out %s ago, was no longer spendable: %v", logins+1, derive, err)
			}
			logins++
			userNonce = nil
		}
		// The user starts a login whenever none is in progress.
		if userNonce == nil && sec%7 == 0 {
			n, err := c.IssueChallenge(ctx, userID, randNonce(t), testChallengeTTL, testChallengeMinUsable, now)
			if err != nil {
				t.Fatalf("user issue at %ds: %v", sec, err)
			}
			userNonce, consumeAt = n, at+derive
		}
		// The attacker asks every second.
		if _, err := c.IssueChallenge(ctx, userID, randNonce(t), testChallengeTTL, testChallengeMinUsable, now); err != nil {
			t.Fatalf("attacker issue at %ds: %v", sec, err)
		}
		if rows := challengeRows(t, c, userID); len(rows) > 2 {
			t.Fatalf("%d challenge rows at %ds, the bound is 2", len(rows), sec)
		}
	}
	if logins < 10 {
		t.Errorf("only %d logins completed in 10 simulated minutes", logins)
	}
}

// The hole in "write a fresh nonce once under a minute is left": a user handed the waiting nonce
// just before that moment has it replaced a second later, while their browser is still deriving.
// Here the user asks with 46s left (over the 45s floor, so they get the waiting nonce), the
// refresh moment passes with an attacker's request 2s later, and the user's signature arrives 40s
// after they asked. It must land.
func TestIssueChallengeNonceHandedOutJustBeforeTheRefreshSurvives(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-issue-edge-" + randomSuffix(t)
	start := time.Now()

	waiting := randNonce(t)
	if _, err := c.IssueChallenge(ctx, userID, waiting, testChallengeTTL, testChallengeMinUsable, start); err != nil {
		t.Fatalf("issue: %v", err)
	}
	// 74s in: 46s left, still over the floor, so the user is handed the waiting nonce.
	userNonce, err := c.IssueChallenge(ctx, userID, randNonce(t), testChallengeTTL, testChallengeMinUsable, start.Add(74*time.Second))
	if err != nil || !bytes.Equal(userNonce, waiting) {
		t.Fatalf("user at 74s = %x, %v; want the waiting nonce", userNonce, err)
	}
	// 76s in: 44s left, under the floor. The attacker's request must write a NEW nonce somewhere
	// else, not replace the one the user is holding.
	if _, err := c.IssueChallenge(ctx, userID, randNonce(t), testChallengeTTL, testChallengeMinUsable, start.Add(76*time.Second)); err != nil {
		t.Fatalf("attacker issue: %v", err)
	}
	// 114s in: the user's signature arrives, 40s after they asked, 6s before the nonce expires.
	if err := c.ConsumeChallenge(ctx, userID, userNonce, start.Add(114*time.Second)); err != nil {
		t.Fatalf("the user's nonce, handed out at 74s, was replaced by the next request: %v", err)
	}
}

// If both slots ever hold a nonce with enough life left, the one expiring later is the one to
// hand out. The write rules never produce that state (see IssueChallenge); this pins the choice
// so a state that was written by hand, or by an older build, still resolves the same way.
func TestIssueChallengeHandsOutTheFresherOfTwo(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-issue-two-" + randomSuffix(t)
	now := time.Now()

	older, newer := randNonce(t), randNonce(t)
	for _, row := range []struct {
		sk    string
		nonce []byte
		ttl   time.Duration
	}{{challengeSlotA, older, 100 * time.Second}, {challengeSlotB, newer, 110 * time.Second}} {
		item, err := attributevalue.MarshalMap(models.Challenge{
			Record: models.Record{PK: "USER#" + userID, SK: row.sk, Type: "Challenge"},
			Nonce:  row.nonce,
			TTL:    now.Add(row.ttl).Unix(),
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.ddb.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(c.table), Item: item}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := c.IssueChallenge(ctx, userID, randNonce(t), testChallengeTTL, testChallengeMinUsable, now)
	if err != nil || !bytes.Equal(got, newer) {
		t.Errorf("handed out %x, %v; want the later-expiring nonce %x", got, err, newer)
	}
}

// Many requests at once, all with different candidate nonces, must agree on one nonce and leave
// one row: the write is conditional, so a lost race re-reads the winner's nonce.
func TestIssueChallengeConcurrent(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-issue-race-" + randomSuffix(t)
	now := time.Now()

	const n = 16
	results := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = c.IssueChallenge(ctx, userID, randNonce(t), testChallengeTTL, testChallengeMinUsable, now)
		}()
	}
	wg.Wait()
	for i := range n {
		if errs[i] != nil {
			t.Fatalf("request %d: %v", i, errs[i])
		}
		if !bytes.Equal(results[i], results[0]) {
			t.Fatalf("request %d was handed a different nonce from request 0", i)
		}
	}
	if rows := challengeRows(t, c, userID); len(rows) != 1 {
		t.Errorf("%d rows after %d concurrent requests, want 1", len(rows), n)
	}
}

// IssueChallenge's guarantee needs the lifetime to exceed twice the floor; arguments that break
// that are refused instead of quietly giving a weaker one.
func TestIssueChallengeRefusesBadArithmetic(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	for _, tc := range []struct{ ttl, floor time.Duration }{
		{90 * time.Second, 45 * time.Second}, // exactly twice: not enough
		{time.Minute, time.Minute},
		{2 * time.Minute, 0},
	} {
		if _, err := c.IssueChallenge(ctx, "test-issue-bad-"+randomSuffix(t), randNonce(t), tc.ttl, tc.floor, time.Now()); err == nil {
			t.Errorf("ttl %s, floor %s accepted", tc.ttl, tc.floor)
		}
	}
}

// A stale nonce must not spend a later, unrelated challenge. With nonces replaced only after they
// expire, the way to get "stale" is an expired one whose slot was rewritten.
func TestConsumeChallengeStaleNonceCannotSpendALaterOne(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-challenge-stale-" + randomSuffix(t)
	now := time.Now()

	first, second := randNonce(t), randNonce(t)
	if _, err := c.IssueChallenge(ctx, userID, first, testChallengeTTL, testChallengeMinUsable, now); err != nil {
		t.Fatalf("issue first: %v", err)
	}
	if _, err := c.IssueChallenge(ctx, userID, second, testChallengeTTL, testChallengeMinUsable, now.Add(testChallengeTTL+time.Second)); err != nil {
		t.Fatalf("issue second: %v", err)
	}

	at := now.Add(testChallengeTTL + time.Second)
	if err := c.ConsumeChallenge(ctx, userID, first, at); !errors.Is(err, ErrChallengeMismatch) {
		t.Errorf("stale nonce consume err = %v, want ErrChallengeMismatch", err)
	}
	if err := c.ConsumeChallenge(ctx, userID, second, at); err != nil {
		t.Errorf("ConsumeChallenge with current nonce: %v", err)
	}
}

// An expired nonce cannot be spent even while its row is still in the table. DynamoDB can leave
// an expired row for up to 48 hours, so "valid for two minutes" has to be checked where the nonce
// is spent, as it is where one is handed out. The row here is real and unswept (the clock is
// simulated, so DynamoDB has not touched it).
func TestConsumeChallengeRefusesAnExpiredNonce(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	userID := "test-challenge-expired-spend-" + randomSuffix(t)
	now := time.Now()
	nonce := randNonce(t)
	if _, err := c.IssueChallenge(ctx, userID, nonce, testChallengeTTL, testChallengeMinUsable, now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if rows := challengeRows(t, c, userID); len(rows) != 1 {
		t.Fatalf("setup: %d rows, want 1", len(rows))
	}

	// At the instant it expires, and after: refused. The row is still there afterwards.
	for _, after := range []time.Duration{testChallengeTTL, testChallengeTTL + time.Hour} {
		if err := c.ConsumeChallenge(ctx, userID, nonce, now.Add(after)); !errors.Is(err, ErrChallengeMismatch) {
			t.Errorf("consume %s in: err = %v, want ErrChallengeMismatch", after, err)
		}
	}
	if rows := challengeRows(t, c, userID); len(rows) != 1 {
		t.Errorf("a refused consume removed the row")
	}
	// One second before expiry it is still good.
	if err := c.ConsumeChallenge(ctx, userID, nonce, now.Add(testChallengeTTL-time.Second)); err != nil {
		t.Errorf("consume 1s before expiry: %v", err)
	}
}

func TestConsumeChallengeNoChallenge(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	err := c.ConsumeChallenge(ctx, "test-no-challenge-"+randomSuffix(t), []byte("any-nonce-value-here-doesnt-matter"), time.Now())
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
