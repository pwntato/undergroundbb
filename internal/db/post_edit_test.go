package db

import (
	"context"
	"errors"
	"testing"
)

// The handler answers 404 for a post it cannot read, so the database's own
// refusal is reached only when the row vanishes between the read and the write
// (the post's expiry). It must still refuse and must not create a row: an
// UpdateItem without its condition would write a tombstone with no author.
func TestDeletePostOfAMissingRowIsRefusedAndWritesNothing(t *testing.T) {
	c := testClient(t)
	gid := newUserID(t)
	sortKey := "POST#2026-10-28#00112233445566ff"
	if err := c.DeletePost(context.Background(), gid, sortKey, gid+"#2026-10-28#00112233445566ff"); !errors.Is(err, ErrPostGone) {
		t.Fatalf("err = %v, want ErrPostGone", err)
	}
	got, err := c.GetPost(context.Background(), gid, sortKey)
	if err != nil || got != nil {
		t.Errorf("a row exists after a refused delete: %+v, %v", got, err)
	}
}
