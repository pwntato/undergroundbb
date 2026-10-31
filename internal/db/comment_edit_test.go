package db

import (
	"context"
	"errors"
	"testing"
)

// The handler answers 404 for a comment it cannot read, so the database's own
// refusal is reachable only when the row vanishes between the read and the
// write (a post's expiry). It must still refuse, and must not create a row:
// an UpdateItem without its condition would write a tombstone with no author.
func TestDeleteCommentOfAMissingRowIsRefusedAndWritesNothing(t *testing.T) {
	c := testClient(t)
	pid := "g-" + newUserID(t) + "#2026-10-28#00112233445566ff"
	if err := c.DeleteComment(context.Background(), pid, "0001"); !errors.Is(err, ErrCommentGone) {
		t.Fatalf("err = %v, want ErrCommentGone", err)
	}
	got, err := c.GetComment(context.Background(), pid, "0001")
	if err != nil || got != nil {
		t.Errorf("a row exists after a refused delete: %+v, %v", got, err)
	}
}
