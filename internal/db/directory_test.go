package db

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/pwntato/undergroundbb/internal/models"
)

// The public group directory (#71). The index is shared by every public group in the table, so each
// test searches under a name prefix of its own (a fresh uuid) and creates its own rows.

func putDirectoryGroup(t *testing.T, c *Client, name, visibility string) string {
	t.Helper()
	gid := newUserID(t)
	putRaw(t, c, map[string]types.AttributeValue{
		"PK": s("GROUP#" + gid), "SK": s("META"), "Type": s("Group"), "Visibility": s(visibility),
		"NamePlaintext": s(name), "DescriptionPlaintext": s("about " + name),
		"GSI1PK": s("PUBLIC#0"), "GSI1SK": s("NAME#" + name + "#" + gid),
	})
	t.Cleanup(func() { removePartitions(t, c, "GROUP#"+gid) })
	return gid
}

func names(es []DirectoryEntry) []string {
	out := make([]string, len(es))
	for i, e := range es {
		out[i] = e.Name
	}
	return out
}

func TestListPublicGroupsFiltersByPrefixInNameOrderWithDuplicates(t *testing.T) {
	c := testClient(t)
	p := newUserID(t) + "-"
	b1 := putDirectoryGroup(t, c, p+"Book Club", models.VisibilityPublic)
	b2 := putDirectoryGroup(t, c, p+"Book Club", models.VisibilityPublic)
	putDirectoryGroup(t, c, p+"Chess", models.VisibilityPublic)
	putDirectoryGroup(t, c, p+"Alpha", models.VisibilityPublic)
	putDirectoryGroup(t, c, newUserID(t)+"-Book Club", models.VisibilityPublic) // another prefix

	all, next, err := c.ListPublicGroups(context.Background(), p, 50, "")
	if err != nil || next != "" {
		t.Fatalf("all = %v next=%q err=%v", names(all), next, err)
	}
	want := []string{p + "Alpha", p + "Book Club", p + "Book Club", p + "Chess"}
	if got := names(all); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("names = %v, want %v", got, want)
	}
	// Two groups with one name are BOTH listed, told apart by id, and carry their description.
	var ids []string
	for _, e := range all {
		if e.Name == p+"Book Club" {
			ids = append(ids, e.GroupID)
			if e.Description != "about "+p+"Book Club" {
				t.Errorf("description = %q", e.Description)
			}
		}
	}
	if len(ids) != 2 || ids[0] == ids[1] || !((ids[0] == b1 && ids[1] == b2) || (ids[0] == b2 && ids[1] == b1)) {
		t.Errorf("duplicate-name ids = %v, want %s and %s", ids, b1, b2)
	}

	narrow, _, err := c.ListPublicGroups(context.Background(), p+"Book", 50, "")
	if err != nil || len(narrow) != 2 {
		t.Errorf("prefix Book = %v, %v", names(narrow), err)
	}
	// Case-sensitive: the index key is the name as typed.
	none, _, err := c.ListPublicGroups(context.Background(), p+"book", 50, "")
	if err != nil || len(none) != 0 {
		t.Errorf("prefix book = %v, %v", names(none), err)
	}
}

func TestListPublicGroupsPagesWithoutRepeatsOrGapsAndNoEmptyLastPage(t *testing.T) {
	c := testClient(t)
	p := newUserID(t) + "-"
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		putDirectoryGroup(t, c, p+n, models.VisibilityPublic)
	}
	var got []string
	cursor := ""
	pages := 0
	for {
		es, next, err := c.ListPublicGroups(context.Background(), p, 2, cursor)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(es) == 0 {
			t.Fatalf("page %d is empty", pages)
		}
		got = append(got, names(es)...)
		if next == "" {
			break
		}
		cursor = next
		if pages > 10 {
			t.Fatal("did not terminate")
		}
	}
	want := []string{p + "a", p + "b", p + "c", p + "d", p + "e"}
	if strings.Join(got, "|") != strings.Join(want, "|") || pages != 3 {
		t.Errorf("got %v in %d pages, want %v in 3", got, pages, want)
	}
	// Exactly one full page: no cursor, so the client is not sent to an empty page.
	es, next, err := c.ListPublicGroups(context.Background(), p, 5, "")
	if err != nil || len(es) != 5 || next != "" {
		t.Errorf("exact page = %d next=%q err=%v", len(es), next, err)
	}
}

func TestListPublicGroupsNeverListsAGroupThatIsNotPublic(t *testing.T) {
	c := testClient(t)
	p := newUserID(t) + "-"
	putDirectoryGroup(t, c, p+"Open", models.VisibilityPublic)
	// A row that carries a directory key but is not public (a state nothing writes): not listed.
	putDirectoryGroup(t, c, p+"Hidden", models.VisibilityPrivate)
	es, _, err := c.ListPublicGroups(context.Background(), p, 50, "")
	if err != nil || len(es) != 1 || es[0].Name != p+"Open" {
		t.Errorf("listing = %v, %v", names(es), err)
	}
}

func TestValidDirectoryCursor(t *testing.T) {
	gid := "11111111-1111-4111-8111-111111111111"
	cases := []struct {
		cursor, prefix string
		want           bool
	}{
		{"NAME#Book#" + gid, "", true},
		{"NAME#Book#" + gid, "Bo", true},
		{"NAME#Book#" + gid, "Ch", false}, // outside the prefix's range
		{"NAME#A#B#" + gid, "A", true},    // a name may contain '#'
		{"NAME#Book#not-a-uuid", "", false},
		{"NAME#Book" + gid, "", false}, // no separator before the gid
		{"USER#x#" + gid, "", false},
		{"", "", false},
		{"NAME#" + gid, "", false},
	}
	for _, tc := range cases {
		if got := ValidDirectoryCursor(tc.cursor, tc.prefix); got != tc.want {
			t.Errorf("ValidDirectoryCursor(%q, %q) = %v, want %v", tc.cursor, tc.prefix, got, tc.want)
		}
	}
}

func TestListPublicGroupsRefusesAMalformedCursor(t *testing.T) {
	c := testClient(t)
	if _, _, err := c.ListPublicGroups(context.Background(), "", 5, "garbage"); err == nil {
		t.Error("malformed cursor accepted")
	}
}
