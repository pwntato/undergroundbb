package backfill

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The backfill Lambda runs under its own role (terraform/backfill.tf), and
// DynamoDB Local does not enforce IAM, so a missing grant would only show up
// in prod and an extra one would never show up at all. This pins the role's
// dynamodb:* actions to exactly the API calls this package makes.

var (
	apiCallRe = regexp.MustCompile(`\bapi\.([A-Z][A-Za-z]+)\(`)
	grantRe   = regexp.MustCompile(`"dynamodb:([A-Za-z]+)"`)
)

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func actionsUsed(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("backfill.go")
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	for _, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		for _, m := range apiCallRe.FindAllStringSubmatch(line, -1) {
			set[m[1]] = true
		}
	}
	return sortedKeys(set)
}

func actionsGranted(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile(filepath.Join("..", "..", "terraform", "backfill.tf"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(src)
	start := strings.Index(s, `data "aws_iam_policy_document" "backfill_policy"`)
	end := strings.Index(s, `resource "aws_iam_role_policy" "backfill"`)
	if start < 0 || end < start {
		t.Fatal("backfill_policy document not found in terraform/backfill.tf")
	}
	set := map[string]bool{}
	for _, m := range grantRe.FindAllStringSubmatch(s[start:end], -1) {
		set[m[1]] = true
	}
	return sortedKeys(set)
}

func TestBackfillRoleGrantsExactlyTheDynamoDBActionsTheBackfillUses(t *testing.T) {
	used := actionsUsed(t)
	// Guard against the scan silently matching nothing.
	if !reflect.DeepEqual(used, []string{"Scan", "UpdateItem"}) {
		t.Fatalf("scan found %v; has the backfill's API call shape changed?", used)
	}
	if granted := actionsGranted(t); !reflect.DeepEqual(used, granted) {
		t.Errorf("terraform/backfill.tf grants dynamodb:%v\ninternal/backfill needs dynamodb:%v", granted, used)
	}
}
