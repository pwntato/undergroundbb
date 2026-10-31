package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pwntato/undergroundbb/internal/models"
)

func comment(path string, ct int) models.Comment {
	return models.Comment{Record: models.Record{SK: "CMT#" + path}, Ciphertext: make([]byte, ct)}
}

func reaction(target, reactor string) models.Reaction {
	return models.Reaction{Record: models.Record{SK: "RXN#" + target + "#" + reactor}}
}

func TestFitThreadPageKeepsAPrefixOfCommentsAndTheReactionsThatBelongToIt(t *testing.T) {
	cs := []models.Comment{comment("0001", 100), comment("0001.0001", 100), comment("0002", 100)}
	rs := []models.Reaction{
		reaction("0000", "a"), reaction("0001", "a"), reaction("0001", "b"),
		reaction("0001.0001", "a"), reaction("0002", "a"),
	}
	one := commentWireSize(cs[0]) + reactionWireSize(rs[0]) + reactionWireSize(rs[1]) + reactionWireSize(rs[2])
	for _, tc := range []struct {
		name         string
		budget       int
		wantC, wantR int
	}{
		{"everything fits", 1 << 20, 3, 5},
		{"only the first comment, with the post's reactions", one, 1, 3},
		{"one byte short of the second comment", one + commentWireSize(cs[1]) + reactionWireSize(rs[3]) - 1, 1, 3},
		{"exactly the second comment", one + commentWireSize(cs[1]) + reactionWireSize(rs[3]), 2, 4},
		{"nothing fits, the first is kept anyway", 1, 1, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, r := fitThreadPage(cs, rs, tc.budget)
			if c != tc.wantC || r != tc.wantR {
				t.Errorf("kept %d comments and %d reactions, want %d and %d", c, r, tc.wantC, tc.wantR)
			}
		})
	}
	if c, r := fitThreadPage(nil, rs[:1], 1); c != 0 || r != 1 {
		t.Errorf("no comments: kept %d and %d, want 0 and the post's reaction", c, r)
	}
}

// The budget compares estimates, so an estimate below the real JSON would let a
// page through that is bigger than it claims.
func TestThreadSizeEstimatesNeverUndercountTheJSON(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	for i, size := range []int{0, 1, 2, 3, 100, 10000} {
		storeCommentSized(t, pid, fmt.Sprintf("%04d", i+1), owner.userID, 0, size)
	}
	for i := 0; i < 4; i++ {
		storeReactionAt(t, pid, "0000", fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i))
		storeReactionAt(t, pid, "0006", fmt.Sprintf("00000000-0000-4000-8000-00000000000%d", i))
	}
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	rows, _, err := h.db.ListComments(context.Background(), pid, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	rxns, err := h.db.ListReactions(context.Background(), pid, "0001", "0006", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Comments) != 6 || len(rows) != 6 || len(out.Reactions) != 8 || len(rxns) != 8 {
		t.Fatalf("got %d/%d comments, %d/%d reactions", len(out.Comments), len(rows), len(out.Reactions), len(rxns))
	}
	for i, c := range out.Comments {
		b, _ := json.Marshal(c)
		if est := commentWireSize(rows[i]); est < len(b) {
			t.Errorf("comment %d: estimate %d is below the %d bytes of JSON", i, est, len(b))
		}
	}
	for i, x := range out.Reactions {
		b, _ := json.Marshal(x)
		if est := reactionWireSize(rxns[i]); est < len(b) {
			t.Errorf("reaction %d: estimate %d is below the %d bytes of JSON", i, est, len(b))
		}
	}
}

// generation is the one number in an entry, so only the overhead constants
// cover it. The longest it can be is the most negative int64, 20 characters.
func TestThreadSizeEstimatesCoverTheLongestGeneration(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	const minInt64 = "-9223372036854775808"
	gen := &types.AttributeValueMemberN{Value: minInt64}
	putCommentRow(t, map[string]types.AttributeValue{
		"PK": s("POST#" + pid), "SK": s("CMT#0001"), "Type": s("COMMENT"),
		"AuthorUserID": s(owner.userID), "SignedDay": s("2026-10-28"), "Generation": gen,
		"Nonce":      &types.AttributeValueMemberB{Value: make([]byte, 12)},
		"Ciphertext": &types.AttributeValueMemberB{Value: make([]byte, 60)},
		"Signature":  &types.AttributeValueMemberB{Value: make([]byte, 64)},
	})
	putCommentRow(t, map[string]types.AttributeValue{
		"PK": s("POST#" + pid), "SK": s("RXN#0001#" + owner.userID), "Type": s("REACTION"), "Generation": gen,
		"Nonce":      &types.AttributeValueMemberB{Value: make([]byte, 12)},
		"Ciphertext": &types.AttributeValueMemberB{Value: make([]byte, 17)},
	})
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	rows, _, err := h.db.ListComments(context.Background(), pid, "", 50)
	if err != nil {
		t.Fatal(err)
	}
	rxns, err := h.db.ListReactions(context.Background(), pid, "0001", "0001", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Comments) != 1 || len(rows) != 1 || len(out.Reactions) != 1 || len(rxns) != 1 {
		t.Fatalf("got %d/%d comments, %d/%d reactions", len(out.Comments), len(rows), len(out.Reactions), len(rxns))
	}
	if out.Comments[0].Generation != math.MinInt64 || out.Reactions[0].Generation != math.MinInt64 {
		t.Fatalf("generations = %d, %d, want the most negative int64", out.Comments[0].Generation, out.Reactions[0].Generation)
	}
	cb, _ := json.Marshal(out.Comments[0])
	if est := commentWireSize(rows[0]); est < len(cb) {
		t.Errorf("comment: estimate %d is below the %d bytes of JSON", est, len(cb))
	}
	xb, _ := json.Marshal(out.Reactions[0])
	if est := reactionWireSize(rxns[0]); est < len(xb) {
		t.Errorf("reaction: estimate %d is below the %d bytes of JSON", est, len(xb))
	}
}

// walkThread reads every page of a thread with the given limit and returns the
// comment paths, the "target/reactor" of every reaction (both in the order
// served) and the number of pages that were cut short of limit by a cursor.
func walkThread(t *testing.T, h *Handler, cookie *http.Cookie, pid string, limit int) (paths, rxns []string, shortPages int, bodies []int) {
	t.Helper()
	cursor := ""
	for page := 0; page < 200; page++ {
		rec := doThread(t, h, cookie, pid, fmt.Sprintf("?limit=%d&cursor=%s", limit, cursor))
		bodies = append(bodies, rec.Body.Len())
		out := decodeThread(t, rec)
		paths = append(paths, threadPaths(out)...)
		for _, x := range out.Reactions {
			rxns = append(rxns, x.Target+"/"+x.ReactorUserID)
		}
		if out.NextCursor == "" {
			return paths, rxns, shortPages, bodies
		}
		if len(out.Comments) < limit {
			shortPages++
		}
		if len(out.Comments) == 0 {
			t.Fatal("a page with a cursor and no comments would never end")
		}
		cursor = out.NextCursor
	}
	t.Fatal("the thread never ended")
	return
}

func seedBusyThread(t *testing.T, pid, author string, comments, reactors int) (wantPaths, wantRxns []string) {
	t.Helper()
	targets := []string{"0000"}
	for i := 1; i <= comments; i++ {
		p := fmt.Sprintf("%04d", i)
		wantPaths = append(wantPaths, p)
		storeCommentSized(t, pid, p, author, 0, 600)
		targets = append(targets, p)
		// A reply to every third comment, so a cut can fall between a comment and
		// its reply.
		if i%3 == 0 {
			r := p + ".0001"
			wantPaths = append(wantPaths, r)
			storeCommentSized(t, pid, r, author, 0, 600)
			targets = append(targets, r)
		}
	}
	// Reactions in thread order: the post's, then each comment's in turn.
	order := append([]string{"0000"}, wantPaths...)
	for _, target := range order {
		for r := 0; r < reactors; r++ {
			id := fmt.Sprintf("00000000-0000-4000-8000-%012d", r)
			storeReactionAt(t, pid, target, id)
			wantRxns = append(wantRxns, target+"/"+id)
		}
	}
	return wantPaths, wantRxns
}

func TestThreadPagesCutByTheBudgetLoseNoCommentAndNoReaction(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	wantPaths, wantRxns := seedBusyThread(t, pid, owner.userID, 14, 5)

	// With room for everything, the walk is the baseline.
	paths, rxns, short, _ := walkThread(t, h, cookie, pid, 100)
	if short != 0 || strings.Join(paths, ",") != strings.Join(wantPaths, ",") || strings.Join(rxns, ",") != strings.Join(wantRxns, ",") {
		t.Fatalf("baseline walk: %d short pages\n%v\n%v", short, paths, rxns)
	}

	// A budget that holds about three comments with their reactions.
	h.threadBudget = 3 * (commentWireSize(comment("0001", 600)) + 5*reactionWireSize(reaction("0001", "00000000-0000-4000-8000-000000000000")))
	paths, rxns, short, bodies := walkThread(t, h, cookie, pid, 100)
	if short == 0 {
		t.Fatal("the budget never cut a page, so this proves nothing")
	}
	if strings.Join(paths, ",") != strings.Join(wantPaths, ",") {
		t.Errorf("comments = %v, want %v", paths, wantPaths)
	}
	if strings.Join(rxns, ",") != strings.Join(wantRxns, ",") {
		t.Errorf("reactions = %v\nwant %v", rxns, wantRxns)
	}
	for i, n := range bodies {
		if n > h.threadBudget {
			t.Errorf("page %d is %d bytes, over the %d budget", i+1, n, h.threadBudget)
		}
	}
}

func TestThreadWithABudgetSmallerThanOneCommentStillMakesProgress(t *testing.T) {
	h, _, pid, owner, cookie := commentFixture(t)
	wantPaths, wantRxns := seedBusyThread(t, pid, owner.userID, 4, 3)
	h.threadBudget = 1
	paths, rxns, _, _ := walkThread(t, h, cookie, pid, 100)
	if strings.Join(paths, ",") != strings.Join(wantPaths, ",") || strings.Join(rxns, ",") != strings.Join(wantRxns, ",") {
		t.Fatalf("comments %v\nreactions %v", paths, rxns)
	}
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if len(out.Comments) != 1 || out.NextCursor != "0001" {
		t.Errorf("first page: %v, cursor %q; want the first comment alone", threadPaths(out), out.NextCursor)
	}
	if got := strings.Join(reactionTargets(out), ","); got != "0000,0000,0000,0001,0001,0001" {
		t.Errorf("first page reactions = %s, want the post's and the first comment's", got)
	}
}

func TestThreadWithNoCommentsServesAllThePostsReactionsWhateverTheBudget(t *testing.T) {
	h, _, pid, _, cookie := commentFixture(t)
	for r := 0; r < 4; r++ {
		storeReactionAt(t, pid, "0000", fmt.Sprintf("00000000-0000-4000-8000-%012d", r))
	}
	h.threadBudget = 1
	out := decodeThread(t, doThread(t, h, cookie, pid, ""))
	if len(out.Reactions) != 4 || out.NextCursor != "" {
		t.Fatalf("%d reactions, cursor %q", len(out.Reactions), out.NextCursor)
	}
}

// A Lambda's synchronous response is limited to 6 MB; the default budget must
// leave room for encoding and for the estimates being rough.
func TestDefaultThreadBudgetLeavesRoomUnderALambdaResponse(t *testing.T) {
	if defaultThreadBudget > 5<<20 {
		t.Errorf("defaultThreadBudget = %d, over 5 MB", defaultThreadBudget)
	}
	h := &Handler{}
	if h.threadBudgetBytes() != defaultThreadBudget {
		t.Error("a zero override must mean the default")
	}
	h.threadBudget = 1234
	if h.threadBudgetBytes() != 1234 {
		t.Error("an override must be used")
	}
}

func TestBase64LenIsTheEncodedLength(t *testing.T) {
	for n := 0; n < 40; n++ {
		if got, want := base64Len(n), base64.StdEncoding.EncodedLen(n); got != want {
			t.Errorf("base64Len(%d) = %d, want %d", n, got, want)
		}
	}
}

// The overhead constants hide a field that is not counted at all, so also check
// that every field the entry carries moves the estimate by what it adds to the
// JSON.
func TestThreadSizeEstimatesCountEveryField(t *testing.T) {
	c := models.Comment{Record: models.Record{SK: "CMT#0001"}, AuthorUserID: "u", SignedDay: "2026-10-28"}
	c0 := commentWireSize(c)
	for name, grown := range map[string]func(models.Comment) models.Comment{
		"nonce":      func(c models.Comment) models.Comment { c.Nonce = make([]byte, 3); return c },
		"ciphertext": func(c models.Comment) models.Comment { c.Ciphertext = make([]byte, 3); return c },
		"signature":  func(c models.Comment) models.Comment { c.Signature = make([]byte, 3); return c },
		"path":       func(c models.Comment) models.Comment { c.SK += "1234"; return c },
		"author":     func(c models.Comment) models.Comment { c.AuthorUserID += "1234"; return c },
		"signed day": func(c models.Comment) models.Comment { c.SignedDay += "1234"; return c },
	} {
		if got := commentWireSize(grown(c)) - c0; got != 4 {
			t.Errorf("comment %s: estimate grew by %d, want 4", name, got)
		}
	}
	x := models.Reaction{Record: models.Record{SK: "RXN#0000#u"}}
	x0 := reactionWireSize(x)
	for name, grown := range map[string]func(models.Reaction) models.Reaction{
		"nonce":      func(x models.Reaction) models.Reaction { x.Nonce = make([]byte, 3); return x },
		"ciphertext": func(x models.Reaction) models.Reaction { x.Ciphertext = make([]byte, 3); return x },
		"key":        func(x models.Reaction) models.Reaction { x.SK += "1234"; return x },
	} {
		if got := reactionWireSize(grown(x)) - x0; got != 4 {
			t.Errorf("reaction %s: estimate grew by %d, want 4", name, got)
		}
	}
}
