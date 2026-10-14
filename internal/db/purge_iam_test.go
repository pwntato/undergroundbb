package db

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The purge Lambda runs under its own role (terraform/purge.tf), and DynamoDB
// Local does not enforce IAM, so a missing grant would only show up in prod
// and an extra one would never show up at all. This pins the role's
// dynamodb:* actions to exactly what cmd/purge uses: every action purge.go
// calls plus BatchWriteItem (batchDelete, in leave.go), and nothing more. In
// particular no Scan, no PutItem and no Transact*: the purge deletes by key.

// purgeActionsUsed returns the DynamoDB actions purge.go uses directly, plus
// the one batchDelete uses on its behalf.
func purgeActionsUsed(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("purge.go")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, m := range ddbCallRe.FindAllStringSubmatch(line, -1) {
			if !ddbCallsIgnored[m[1]] {
				set[m[1]] = true
			}
		}
		for _, m := range txItemRe.FindAllStringSubmatch(line, -1) {
			set[txItemAction[m[1]]] = true
		}
	}
	// batchDelete is shared with leave.go, so it is not scanned from there.
	leave, err := os.ReadFile("leave.go")
	if err != nil {
		t.Fatal(err)
	}
	fn := string(leave)
	start := strings.Index(fn, "func (c *Client) batchDelete(")
	if start < 0 {
		t.Fatal("batchDelete not found in leave.go; the purge IAM test needs updating")
	}
	body := fn[start:]
	if end := strings.Index(body[1:], "\nfunc "); end >= 0 {
		body = body[:end+1]
	}
	for _, m := range ddbCallRe.FindAllStringSubmatch(body, -1) {
		set[m[1]] = true
	}
	return sorted(set)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// purgeGrantedActions returns the dynamodb:* actions in terraform/purge.tf's
// purge_policy document.
func purgeGrantedActions(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "terraform", "purge.tf"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, `data "aws_iam_policy_document" "purge_policy"`)
	if start < 0 {
		t.Fatal("purge_policy document not found in terraform/purge.tf")
	}
	end := strings.Index(s[start:], `resource "aws_iam_role_policy" "purge"`)
	if end < 0 {
		t.Fatal("end of purge_policy document not found in terraform/purge.tf")
	}
	set := map[string]bool{}
	for _, m := range grantRe.FindAllStringSubmatch(s[start:start+end], -1) {
		set[m[1]] = true
	}
	return sorted(set)
}

func TestPurgeRoleGrantsExactlyTheDynamoDBActionsThePurgeUses(t *testing.T) {
	used := purgeActionsUsed(t)
	// Guard against the scan silently matching nothing.
	for _, a := range []string{"Query", "GetItem", "DeleteItem", "UpdateItem", "BatchWriteItem"} {
		found := false
		for _, u := range used {
			found = found || u == a
		}
		if !found {
			t.Fatalf("scan found no use of %s; has the purge code or db client been renamed? used = %v", a, used)
		}
	}
	granted := purgeGrantedActions(t)
	if !reflect.DeepEqual(used, granted) {
		t.Errorf("terraform/purge.tf grants dynamodb:%v\ncmd/purge needs        dynamodb:%v", granted, used)
	}
}
